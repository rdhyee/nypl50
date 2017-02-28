from __future__ import print_function
__all__ = ['GitenbergJob', 'GitenbergTravisJob', 'ForkBuildRepo', 'BuildRepo', 'BuildRepo2']

# import github3.py

from abc import ABCMeta, abstractmethod
import base64
import time, datetime
from itertools import islice
import re
import sys
import traceback


import yaml

from collections import (namedtuple, OrderedDict)

LastBuild = namedtuple('LastBuild', ['number', 'id', 'created', 'started_at', 'finished_at', 'duration', 'state'])
Buildability = namedtuple('Buildability', ['buildable', 'has_metadata', 'has_source'])

import arrow
from sqlalchemy import or_

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import github3
from github3 import GitHubError
from github3.repos.release import Release

import gitenberg

from gitenberg import metadata
import requests
import semantic_version
from travispy import TravisPy

from second_folio import (travis_template, slugify)
from gitenberg_db import (Repo, create_session)


GH_RATE_BUFFER = 200

class GitenbergJob(object):
    def __init__(self, username, password, repo_name, repo_owner,
               update_travis_commit_msg,
               tag_commit_message):

        self.gh = github3.login(username, password=password)
        self.gh_repo = self.gh.repository(repo_owner, repo_name)
        self.repo_name = repo_name
        self.repo_owner = repo_owner
        self.repo_slug = "{}/{}".format(repo_owner, repo_name)
        self.update_travis_commit_msg = update_travis_commit_msg
        self.tag_commit_message = tag_commit_message

        self._metadata = None
        self._root_tree = None

    def asciidoc_in_repo_root(self, branch ='master'):
        """return list of asciidocs in the root of repo"""
 
        return [hash_.path 
                for hash_ in self.root_tree(branch)
                if hash_.path.endswith('.asciidoc')]

    def create_or_update_file(self, path, message, content, branch='master', ci_skip=True):
    
        message += ' [ci skip]' if ci_skip else ''
        
        path_content =  self.gh_repo.contents(path, ref=branch)
        
        if path_content is None:
            data = {
                'path': path,
                'message': message,
                'content': content,
                'branch': branch
            }

            commit = self.gh_repo.create_file(**data)
  
        else:
            data = {
                'message': message,
                'content': content,
            }

            commit = path_content.update(**data)
            
        return (commit, path_content is None)

    def ebooks_in_github_release(self, tag):
        """
        returns a list of (book_type, book_name) for a given GitHub release (specified by 
        owner, name, tag).  token is a GitHub authorization token -- useful for accessing
        higher rate limit in the GitHub API
        """

        # epub, mobi, pdf, html, text
        # map mimetype to file extension
        EBOOK_FORMATS = {'application/epub+zip':'epub',
                     'application/x-mobipocket-ebook': 'mobi',
                     'application/pdf': 'pdf',
                     'text/plain': 'text',
                     'text/html':'html'}


        release = self.release_from_tag(tag)
        if release is not None:
            assets = release.iter_assets()
            return [(EBOOK_FORMATS.get(asset.content_type), asset.name) 
                    for asset in assets 
                    if EBOOK_FORMATS.get(asset.content_type) is not None]   
        else:
            return []

    def root_tree (self, branch='master'):
        
        if self._root_tree is None:
            repo = self.gh_repo
            repo_branch = repo.branch(branch)
            tree = repo.tree(repo_branch.commit.sha)
            self._root_tree = tree.tree

        return self._root_tree
    
    def in_root_tree(self, path):
        return path in [hash_.path for hash_ in self.root_tree()]

    def gh_hash(self, path, root_sha=None, branch="master"):

        repo_branch = self.gh_repo.branch(branch)
        if root_sha is None:
            root_sha = repo_branch.commit.sha

        # get rid of trailing and leading '/'
        path = re.sub(r"^\/|\/$", "", path)

        if not(path):
            return repo_branch.commit

        path_parts = path.strip().split("/")

        # check for existence of path_parts[0]

        try:
            tree = self.gh_repo.tree(root_sha).tree
        except GitHubError as e:
            if e.code == 422:
                return None
            else:
                raise e

        for hash_ in tree:
            if hash_.path == path_parts[0]:
                if len(path_parts) == 1:
                    return hash_
                else:
                    # check rest of path
                    return self.gh_hash("/".join(path_parts[1:]), root_sha=hash_.sha, branch=branch)

        return None

    def gh_tree(self, sha):
        try:
            tree = self.gh_repo.tree(sha).tree
        except:
            return []
        else:
            return [hash_.path
                for hash_ in tree]

    def buildable(self):

        has_metadata = self.gh_repo.contents("metadata.yaml", ref="master") is not None
        has_source = self.source_book() is not None
        buildable = has_metadata and has_source

        return Buildability(
            buildable,
            has_metadata,
            has_source
            )

    def source_book(self):

        """
        return the path of document to use as the source for building epub
        """

        repo_id = self.repo_name.split("_")[-1]
        repo_htm_dir = "{repo_id}-h".format(repo_id=repo_id)
        repo_htm_path = "{repo_id}-h/{repo_id}-h.htm".format(repo_id=repo_id)

        possible_paths = ["book.asciidoc",
                          repo_htm_path,
                          "{}-0.txt".format(repo_id),
                          "{}-8.txt".format(repo_id),
                          "{}.txt".format(repo_id),
                         ]

        # calculate relevant hashes in repo

        hashes = self.gh_tree(self.gh_hash("").sha)
        if repo_htm_dir in hashes:
            hashes += [repo_htm_dir + "/" + path for path in self.gh_tree(self.gh_hash(repo_htm_dir).sha)]

        # return the first match

        for path in possible_paths:
            if path in hashes:
                return path

        return None
        
    def update_travis_and_commit (self, write_changes=True, update_travis=True, tag_commit=True):
        if update_travis:
            (template_result, template_written, commit) =  self.update_travis_template(write_changes=write_changes)
        else:
            (template_result, template_written, commit)  = (None, None, None)
        
        if tag_commit:
            (_version, _next_version, metadata_updated, commit, tag) = self.tag_commit(write_changes=write_changes)
        else:
            (_version, _next_version, metadata_updated, commit, tag) = (None, None, None, None, None)
        
        return [(template_result, template_written, commit),
               (_version, _next_version, metadata_updated, commit, tag)]
        
    def metadata(self):
        """
        returns a metadata.pandata.Pandata object for repo
        """

        if self._metadata is None:
            # metadata_url = "https://raw.githubusercontent.com/{owner}/{repo_name}/master/metadata.yaml".format(owner=self.repo_owner,
            #                                                                       repo_name=self.repo_name)

            # self._metadata = metadata.pandata.Pandata(metadata_url)

            self._metadata = metadata.pandata.Pandata(datafile=None)
            md_hash = self.gh_repo.contents("metadata.yaml")
            # if the file exists, load the content
            if md_hash is not None:
                self._metadata.metadata = yaml.safe_load(md_hash.decoded)
            return self._metadata
        else:
            return self._metadata
        
    def update_travis_template(self, write_changes=True, template=None, encrypted_key=None):
        """
        compute (and optionally write) .travis.yml based on the template and current metadata.yaml 

        repo: github3.py representation of repository
        """
        template_written = False

        if template is None:
            template = travis_template()
        
        md = self.metadata()
        repo_name = md.metadata.get("_repo")
        # epub_title = slugify(md.metadata.get("title"))
        # go for the default
        # https://github.com/gitenberg-dev/metadata/blob/394dbd77bbb868d43b9f3511914b5df12f571063/gitenberg/metadata/pandata.py#L167
        epub_title = 'book'

        # pick from rep
        if encrypted_key is None:
            encrypted_key = self.gh_repo.contents(".travis.deploy.api_key.txt", ref='master').decoded.decode('utf-8')

        template_vars =  {
            'epub_title': epub_title,
            'encrypted_key': encrypted_key,
            'repo_name': repo_name,
            'repo_owner': self.repo_owner
        }

        template_result = template.render(**template_vars)

        if write_changes:
            # how to write to file 
            content = self.gh_repo.contents('.travis.yml', ref='master')
            data = {
                'message': self.update_travis_commit_msg,
                'content': template_result.encode('utf-8'),
            }

            commit = content.update(**data)
        else:
            commit = None

        return (template_result, template_written, commit)

    def version(self):
        try:
            md = self.metadata()
            return semantic_version.Version(md.metadata.get("_version"))
        except:
            return None

    def next_version(self, version_type='patch'):
        """
        can be overriden -- by default next patch
        """

        assert version_type in ('patch', 'minor', 'major')

        try:
            _version = self.version()
            next_func = getattr(_version, "next_{}".format(version_type))
            return next_func()
        except:
            return None
        
    def tag_commit(self, version_type='patch', write_changes=True):
        """
        github3.py representation of repository
        returns current version, next version, whether metadata updated, commit
        """

        _version = unicode(self.version())
        _next_version = unicode(self.next_version())

        if write_changes:

            # how to write to file 
            content = self.gh_repo.contents('metadata.yaml', ref='master')
            self.metadata().metadata["_version"] =  _next_version
            data = {
                'message': self.tag_commit_message,
                'content': yaml.safe_dump(self.metadata().metadata,default_flow_style=False,
                    allow_unicode=True)
            }
            commit = content.update(**data)

            # also tag the commit
            tag_data =  {
                'tag': _next_version,
                'message': _next_version,
                'sha': commit.sha,
                'obj_type': 'commit',
                'tagger': {
                    'name': self.gh.user().name,
                    'email': self.gh.user().email if self.gh.user().email else 'nobody@example.com',
                    'date': arrow.utcnow().isoformat()
                },
                'lightweight': False
            }

            tag = self.gh_repo.create_tag(**tag_data)

            metadata_updated = True
        else:
            commit = None
            tag = None
            metadata_updated = False

        return (_version, _next_version, metadata_updated, commit, tag)
    
    def release_from_tag(self, tag_name):
        """Get a release by tag name.
        release_from_tag() returns a release with specified tag
        while release() returns a release with specified release id
        :param str tag_name: (required) name of tag
        :returns: :class:`Release <github3.repos.release.Release>`
        """
        
        repo = self.gh_repo
        url = repo._build_url('releases', 'tags', tag_name,
                              base_url=repo._api)
        json = repo._json(repo._get(url), 200)
        return Release(json, repo) if json else None

    def status (self):
        
        files_of_interest = ['metadata.yaml', 'book.asciidoc', 'cover.jpg', 
                            '.travis.yml', '.travis.deploy.api_key.txt']
        
        version = self.version()
        ebooks_in_latest_github_release = self.ebooks_in_github_release(tag=unicode(version)) \
              if version is not None else []
        
        _status = {
            'repo_owner': self.repo_owner,
            'repo_name': self.repo_name,
            'asciidocs': self.asciidoc_in_repo_root(),
            'version': unicode(version),
            'ebooks_in_latest_github_release': ebooks_in_latest_github_release,
            'ebooks_in_release_count': len(ebooks_in_latest_github_release),
            'root_hashes': [hash_.path for hash_ in self.root_tree()]
        }
        
        _status.update(dict([(path, self.in_root_tree(path)) for path in files_of_interest]))

        return _status
    
    def status_latest_epub(self):
        return requests.head(self.url_latest_epub()).status_code

    def url_latest_epub(self):
        """
        repo is a github3.py repo
        """

        md = self.metadata()
        epub_title = slugify(md.metadata.get("title"))
        tag = md.metadata.get("_version")
        url = "https://github.com/GITenberg/{}/releases/download/{}/{}.epub".format(self.repo_name, tag, epub_title)
        return url

    def gh_ratelimit_remaining(self):
        return self.gh.ratelimit_remaining
 
class GitenbergTravisJob(GitenbergJob):
    def __init__(self, username, password, repo_name, repo_owner,
               update_travis_commit_msg,
               tag_commit_message, github_token=None, access_token=None, repo_token=None):

        """A subclass of GitenbergJob that adds travis-ci related functionality

        Keyword arguments:
        username -- GitHub username
        password -- GitHub password
        repo_name -- name of Gitenberg repo (e.g., "Moby-Dick--Or-The-Whale_2701")
        repo_owner -- e.g., 'GITenberg' for https://github.com/gitenberg/At-the-Sign-of-the-Eagle_6218
        update_travis_commit_msg -- the git commit message for the update commit
        tag_commit_message -- the git commit message for the tagging commit
        github_token (optional) -- a GitHub token that is ued to obtain travis access token
        access_token (optional) -- the travis access token corresponding to GitHub account
        repo_token (optional) -- the travis token for building the given repo
        """
        
        super(GitenbergTravisJob, self).__init__(username, password, repo_name, repo_owner,
               update_travis_commit_msg,
               tag_commit_message)
        
        self.username = username
        self.password = password
        
        self._github_token = github_token
        self._access_token = access_token

        # if access_token is given, use it
        # the access token corresponds to the output of the travis cli operation
        # `travis token`
        if access_token is not None:
            self.travis = TravisPy(access_token)
        # otherwise, we can pass a GitHub token to travis
        else:
            self.travis = TravisPy.github_auth(self.github_token())

        self._repo_token = repo_token    
        self._travis_repo_public_key = None

        if self.gh_repo is not None:
            self.travis_repo = self.travis.repo(self.repo_slug)
       
        
    def public_key_for_travis_repo(self):
        if self._travis_repo_public_key is None:
            self._travis_repo_public_key =  requests.get("https://api.travis-ci.org/repos/{}/{}/key".format(self.repo_owner,
                                        self.repo_name)).json()['key']
        return self._travis_repo_public_key


    def github_token(self):
        """
        use the GitHub token in the parameters; otherwise create a new GitHub token with the appropropriate permissions

        """

        if self._github_token is not None:
            return self._github_token
        
        token_note = "token for travis {}".format(datetime.datetime.utcnow().isoformat())
        token = self.gh.authorize(self.username, self.password, 
                             scopes=('read:org', 'user:email', 'repo_deployment', 
                                     'repo:status', 'write:repo_hook'), note=token_note)

        self._github_token = token.token
        return self._github_token
    
    def repo_token(self, from_repo_owner='GITenberg', create_duplicate=False):

        if self._repo_token is not None:
            return self._repo_token
        
        token_note = "automatic releases for {}/{}".format(self.repo_owner, self.repo_name)

        try:
            token = self.gh.authorize(self.username, self.password, scopes=('public_repo'), note=token_note)
        except Exception as e:
            raise e # for now
            if self._authorization_description_already_exists(e):
                # try again with a new description
                if create_duplicate:
                    token_note += " " + datetime.datetime.utcnow().isoformat()
                    token = self.gh.authorize(self.username, self.password, scopes=('public_repo'), note=token_note)
                else:
                    raise Exception('repo token already exists for {}'.format(self.repo_slug))
            else:
                raise e

        self._repo_token = token.token
        return self._repo_token

    def delete_repo_token (self):
        for auth in self.gh.iter_authorizations():
            if auth.name == "automatic releases for {}/{}".format(self.repo_owner, self.repo_name):
                auth.delete()
                return True

        return False
    
    def travis_encrypt(self, token_to_encrypt):
        """
        return encrypted version of token_to_encrypt 
        """
        
        # token_to_encrypt has to be string
        # if's not, assume it's unicode and enconde in utf-8
        
        if isinstance(token_to_encrypt, unicode):
            token_string = token_to_encrypt.encode('utf-8')
        else:
            token_string = token_to_encrypt
        
        repo_public_key_text = self.public_key_for_travis_repo()

        pubkey = repo_public_key_text.encode('utf-8')

        if 'BEGIN PUBLIC KEY' in pubkey:
            repo_public_key = serialization.load_pem_public_key(pubkey,
                backend=default_backend())
        elif 'BEGIN RSA PUBLIC KEY' in pubkey:
            # http://stackoverflow.com/a/32804289
            b64data = '\n'.join(pubkey.splitlines()[1:-1])
            derdata = base64.b64decode(b64data)
            repo_public_key = serialization.load_der_public_key(derdata,
                default_backend())
        else:
            raise Exception ('cannot parse repo public key')

        ciphertext = repo_public_key.encrypt(
         token_string,
         padding.PKCS1v15()
        )

        return base64.b64encode(ciphertext)
    
    def travis_last_build_status(self, refresh=False):

        if refresh:
            self.travis_repo = self.travis.repo(self.repo_slug)

        try:
            last_build = self.travis_repo.last_build
        except KeyError:
            return LastBuild (
                None, None, None, None, None, None, None
            )
        else:
            return LastBuild(
                self.travis_repo.last_build_number,
                self.travis_repo.last_build_id,
                self.travis_repo.last_build.created,
                self.travis_repo.last_build_started_at,
                self.travis_repo.last_build_finished_at,
                self.travis_repo.last_build_duration,
                self.travis_repo.last_build_state
            )


    def status(self, refresh_travis=False):
        _status =  super(GitenbergTravisJob, self).status()

        last_build = self.travis_last_build_status(refresh_travis)
        _status.update({
            'last_build_number': last_build.number,
            'last_build_id': last_build.id,
            'last_build_created': last_build.created,
            'last_build_started_at': last_build.started_at,
            'last_build_finished_at': last_build.finished_at,
            'last_build_duration': last_build.duration,
            'last_build_state': last_build.state,
            })

        return _status
    
    @staticmethod
    def _authorization_description_already_exists(e):
        """
        Given an exception e when trying to create a token, is the exception the result of a duplicate description
        """
        if (e.code == 422 and 
            e.message == u'Validation Failed' and 
            (u'already_exists', u'description') in [(error['code'], error['field']) for error in e.errors]):
            return True
        else:
            return False

class ForkBuildRepo(GitenbergTravisJob):


    def fork_repo(self, from_repo_owner='GITenberg'):
        from_repo = self.gh.repository(from_repo_owner, self.repo_name)

        # fork if necessary
        if self.gh_repo is None:
            self.gh_repo = from_repo.create_fork()

        return self.gh_repo


    def fork_and_build_gitenberg_repo(self, from_repo_owner='GITenberg', 
                                      create_duplicate_token=False,
                                      update_repo_token_file=True):
        """

        """

        from_repo = self.gh.repository(from_repo_owner, self.repo_name)
        
        # fork if necessary
        if self.gh_repo is None:
            self.gh_repo = from_repo.create_fork()
            # instantiate self.travis_repo
            self.travis.user().sync()
            
            self.travis_repo = self.travis.repo(self.repo_slug)
           
        
        # make sure it's active
        if not self.travis_repo.enable():
            raise Exception("unable to enable travis repo:{}".format(self.repo_slug))
    
        # self.repo_token() might be None or a new generated token.

        try:
            encrypted_key = self.travis_encrypt(self.repo_token())
        except:
            # if an exception, try reading from existing .travis.deploy.api_key.txt
            encrypted_key = self.gh_repo.contents(".travis.deploy.api_key.txt", ref='master').decoded
            if encrypted_key is None:
                raise Exception ('cannot get or generate an encrypted key')

        
        # update .travis.deploy.api_key.txt if requested
        if update_repo_token_file:
            self.create_or_update_file(
                 path = ".travis.deploy.api_key.txt", 
                 message = "update .travis.deploy.api_key.txt with new encrypted token",
                 content = encrypted_key,
                 ci_skip = True)
            
        #  update .travis.yml
        
        self.create_or_update_file(
            path = ".travis.yml",
            message = "update .travis.yml with new token and repo_owner",
            content = self.update_travis_template(write_changes=False, 
                                encrypted_key=encrypted_key)[0].encode('utf-8'),
            ci_skip = True
        )

        # update version and tag commit -- should fire off a travis build
        tag_result = self.tag_commit(version_type='patch', write_changes=True)
        return tag_result
        
class BuildRepo(GitenbergTravisJob):

    def fix_repo_name (self, *args, **kwargs):
        # check whether repo_name in metadata.yaml and .travis.yml match the repo name
        md = self.metadata().metadata
        if md.get('_repo') != self.repo_name:
            # fix metadata.yaml
            md['_repo'] = self.repo_name
            result = self.create_or_update_file(
                 path = "metadata.yaml",
                 message = "fix repo name in metadata.yaml",
                 content = yaml.safe_dump(md,default_flow_style=False,
                      allow_unicode=True),
                 ci_skip = True)
            return result
        else:
            return None
        
    def run(self, from_repo_owner='GITenberg',
              create_duplicate_token=False,
              update_repo_token_file=True,
              load_repo_token=True,
              fix_repo_name=False):
        """

        """

        
        # make sure it's active
        if not self.travis_repo.enable():
            raise Exception("unable to enable travis repo:{}".format(self.repo_slug))
    
        if load_repo_token:
            try:
                encrypted_key = self.gh_repo.contents(".travis.deploy.api_key.txt").decoded
            except:
                encrypted_key = self.travis_encrypt(self.repo_token())
        else:
            encrypted_key = self.travis_encrypt(self.repo_token())

        if fix_repo_name:
            self.fix_repo_name()
        
        # update .travis.deploy.api_key.txt if requested
        if update_repo_token_file:
            self.create_or_update_file(
                 path = ".travis.deploy.api_key.txt", 
                 message = self.update_travis_commit_msg if self.update_travis_commit_msg \
                    else "update .travis.deploy.api_key.txt with new encrypted token",
                 content = encrypted_key,
                 ci_skip = True)
            
        #  update .travis.yml
        
        self.create_or_update_file(
            path = ".travis.yml",
            message = self.tag_commit_message if self.tag_commit_message \
               else "update .travis.yml with new token and repo_owner",
            content = self.update_travis_template(write_changes=False, 
                                encrypted_key=encrypted_key)[0].encode('utf-8'),
            ci_skip = True
        )

        # update version and tag commit -- should fire off a travis build
        tag_result = self.tag_commit(version_type='patch', write_changes=True)
        return tag_result
    
class BuildRepo2(BuildRepo):
    def next_version(self, version_type='patch'):
        """
        can be overriden -- by default next patch
        """

        assert version_type in ('patch', 'minor', 'major')

        import semantic_version
        
        _version = self.version()
        if _version < semantic_version.Version('0.1.0'):
            return semantic_version.Version('0.1.0')
        else:
            next_func = getattr(_version, "next_{}".format(version_type))
            return next_func()


"""
https://github.com/rdhyee/gitberg
had to download https://www.gutenberg.org/cache/epub/feeds/rdf-files.tar.bz2
and configure /Users/raymondyee/Library/Application Support/gitberg/config.yaml (Mac)
to pick up Gutenberg metadata 
"""

def repo_md(repo_id):

    b = gitenberg.Book(repo_id)
    b.parse_book_metadata()

    return b.meta.metadata 

class MetadataWrite(GitenbergJob):
    
    def run(self, overwrite=False):
        try:
            import gitenberg

            # check whether metadata file already exists
            if (not overwrite and
                self.gh_repo.contents("metadata.yaml", ref="master") is not None):
                return (self.repo_name, False)

            repo_id = self.repo_name.split("_")[-1]
            md = repo_md(repo_id)
            # add version
            md["_version"] = "0.0.1"

            # need to make sure _repo is actually _repo_name
            md["_repo"] = self.repo_name

            # add keywords 
            subjects = md.get("subjects")
            if 'GITenberg' not in subjects:
                subjects.append('GITenberg')
            md["subjects"] = subjects

            result = self.create_or_update_file(
                             path = "metadata.yaml", 
                             message = "write metadata.yaml",
                             content = yaml.safe_dump(md,default_flow_style=False,
                                  allow_unicode=True),
                             ci_skip = True)
            return (self.repo_name, result)
        except Exception as e:
            return (self.repo_name, e)

class RepoNameFixer(BuildRepo):

    def run (self, *args, **kwargs):
        # check whether repo_name in metadata.yaml and .travis.yml match the repo name
        md = self.metadata().metadata
        if md.get('_repo') != self.repo_name:
            # fix metadata.yaml
            md['_repo'] = self.repo_name
            result = self.create_or_update_file(
                 path = "metadata.yaml",
                 message = "fix repo name in metadata.yaml",
                 content = yaml.safe_dump(md,default_flow_style=False,
                      allow_unicode=True),
                 ci_skip = True)

            # do rest of run
            return super(RepoNameFixer, self).run(*args, **kwargs)
        else:
            return None

class GitenbergJobRunner:
    __metaclass__ = ABCMeta

    def __init__(self, dbfname, gh_username, gh_password, access_token=None, max_exceptions=None):
        self.dbfname = dbfname
        self.gh_username = gh_username
        self.gh_password = gh_password
        self.access_token = access_token
        self.gh = github3.login(gh_username, password=gh_password)
        self._session = None
        self.results = OrderedDict()
        self.max_exceptions = max_exceptions
        self.n_exceptions = 0

    def countdown(self, n, delta=0.5):
        now = arrow.now()
        then = now + datetime.timedelta(seconds=n)
        while now < then:
            print ("\r{}".format(then - now), end="")
            time.sleep(delta)
            now = arrow.now()

    def exceptions(self):
        return [item[0] for item in self. results.items() if isinstance(item[1][0], Exception)]

    def repos(self, n=None):
        """
        by default return all repos
        """

        return islice((self.session().query(Repo)),n)

    def repo_names(self, n=None):
        return (repo.repo_name for repo in self.repos(n))

    def run(self, n=None):
        for (i, repo) in enumerate(self.repos(n)):
            repo_name = repo.repo_name

            try:
                self.run_job(repo)
            except Exception, e:
                (exc_type, exc_value, exc_tb) = sys.exc_info()
                stack_trace = " ".join(traceback.format_exception(exc_type, exc_value, exc_tb))

                self.results[repo_name] = (e, stack_trace)
                self.n_exceptions += 1
                if (self.max_exceptions is not None) and (self.n_exceptions >= self.max_exceptions):
                    print (e, stack_trace)
                    break

            print ("\r{}: {}".format(i, self.results[repo_name]), end="")
            time.sleep(0.5)

            if self.gh.ratelimit_remaining < GH_RATE_BUFFER:
                print ("github rate limit reached")
                dt = arrow.get(self.gh.rate_limit()['rate']['reset']) - arrow.now()
                self.countdown(dt.seconds)

    @abstractmethod
    def run_job(self, repo):
        pass

    def session(self):
        if self._session is None:
            self._session = create_session(self.dbfname)
        return self._session

class MetadataWriterRunner(GitenbergJobRunner):

    def repos(self, n=None):

        return islice((self.session().query(Repo)
         .filter(Repo.metadata_written == None)
         ),n)

    def run_job(self, repo):

        repo_name = repo.repo_name

        bj = MetadataWrite(username=self.gh_username, password=self.gh_password,
               repo_name=repo_name,
               repo_owner = "GITenberg",
               update_travis_commit_msg="first version of metadata.yaml",
               tag_commit_message="first version of metadata.yaml")

        self.results[repo_name] = (bj, bj.run(overwrite=False))

        repo.updated = arrow.now().isoformat()
        repo.metadata_written = arrow.now().isoformat()

        self.session().commit()

class RepoJobRunner(GitenbergJobRunner):

    def repos(self, n):
        return islice((self.session().query(Repo)
            .filter(or_(Repo.buildable == None, Repo.buildable == True))
            .filter(Repo.datebuilt == None)
            .filter(Repo.metadata_written != None)
         ),n)

    def run_job(self, repo):
        repo_name = repo.repo_name

        bj = BuildRepo2(username=self.gh_username,
                password=self.gh_password,
                repo_name=repo_name,
                repo_owner='GITenberg',
                update_travis_commit_msg='build using gitenberg.travis',
                tag_commit_message='build using gitenberg.travis',
                access_token=self.access_token)

        #self.results[repo_name] = (bj, bj.run())

        buildable = bj.buildable()

        repo.buildable = buildable.buildable
        repo.has_source = buildable.has_source
        repo.has_metadata = buildable.has_metadata

        if buildable.buildable:
            self.results[repo_name] = (bj, bj.run())
            repo.datebuilt = arrow.now().isoformat()
        else:
            self.results[repo_name] = (bj, False)

        # just mark as started

        repo.updated = arrow.now().isoformat()

        self.session().commit()

class StatusUpdateRunner(GitenbergJobRunner):

    def repos(self, n):
        return islice((self.session().query(Repo)
                .filter(Repo.datebuilt != None)
                .filter(Repo.last_build_id == None)
         ),n)

    def run_job(self, repo):
        repo_name = repo.repo_name

        bj = BuildRepo2(username=self.gh_username,
                password=self.gh_password,
                repo_name=repo_name,
                repo_owner='GITenberg',
                update_travis_commit_msg='build using gitenberg.travis',
                tag_commit_message='build using gitenberg.travis',
                access_token=self.access_token)

        #self.results[repo_name] = (bj, bj.run())

        status = bj.status()
        self.results[repo_name] = status

        repo.version = status['version']
        repo.ebooks_in_release_count = status['ebooks_in_release_count']
        repo.last_build_id = status['last_build_id']
        repo.last_build_state = status['last_build_state']

        repo.updated = arrow.now().isoformat()

        self.session().commit()
