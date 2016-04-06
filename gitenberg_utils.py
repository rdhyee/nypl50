__all__ = ['GitenbergJob', 'GitenbergTravisJob', 'ForkBuildRepo', 'BuildRepo', 'BuildRepo2']

# import github3.py

import base64
import datetime
import yaml

import arrow
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import github3
from github3.repos.release import Release

from gitenberg import metadata
import requests
import semantic_version
from travispy import TravisPy

from second_folio import (travis_template, slugify)


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
            self._metadata.metadata = yaml.safe_load(self.gh_repo.contents("metadata.yaml").decoded)

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
        epub_title = slugify(md.metadata.get("title"))

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
        md = self.metadata()
        return semantic_version.Version(md.metadata.get("_version"))

    def next_version(self, version_type='patch'):
        """
        can be overriden -- by default next patch
        """

        assert version_type in ('patch', 'minor', 'major')

        _version = self.version()
        next_func = getattr(_version, "next_{}".format(version_type))
        return next_func()
        
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
    
    def url_latest_epub(self):
        """
        repo is a github3.py repo
        """
        
        md = self.metadata()
        epub_title = slugify(md.metadata.get("title"))
        tag = md.metadata.get("_version")
        url = "https://github.com/GITenberg/{}/releases/download/{}/{}.epub".format(self.repo_name, tag, epub_title)
        return url
    
    def status_latest_epub(self):
        return requests.head(self.url_latest_epub()).status_code

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

        return [(EBOOK_FORMATS.get(asset.content_type), asset.name) 
                for asset in release.iter_assets() 
                if EBOOK_FORMATS.get(asset.content_type) is not None]   

class GitenbergTravisJob(GitenbergJob):
    def __init__(self, username, password, repo_name, repo_owner,
               update_travis_commit_msg,
               tag_commit_message, travis_token=None, repo_token=None):
        
        super(GitenbergTravisJob, self).__init__(username, password, repo_name, repo_owner,
               update_travis_commit_msg,
               tag_commit_message)
        
        self.username = username
        self.password = password
        
        self._travis_token = travis_token
        if travis_token is None:
            self._travis_token = self.travis_token()
            
        self._repo_token = repo_token    
        self._travis_repo_public_key = None
 
        self.travis = TravisPy.github_auth(self.travis_token())
        if self.gh_repo is not None:
            self.travis_repo = self.travis.repo(self.repo_slug)
       
        
    def public_key_for_travis_repo(self):
        if self._travis_repo_public_key is None:
            self._travis_repo_public_key =  requests.get("https://api.travis-ci.org/repos/{}/{}/key".format(self.repo_owner,
                                        self.repo_name)).json()['key']
        return self._travis_repo_public_key


    def travis_token(self):

        if self._travis_token is not None:
            return self._travis_token
        
        token_note = "token for travis {}".format(datetime.datetime.utcnow().isoformat())
        token = self.gh.authorize(self.username, self.password, 
                             scopes=('read:org', 'user:email', 'repo_deployment', 
                                     'repo:status', 'write:repo_hook'), note=token_note)

        return token.token
    
    def repo_token(self, from_repo_owner='GITenberg', create_duplicate=False):
        """
       
        """

        if self._repo_token is not None:
            return self._repo_token
        
        token_note = "automatic releases for {}/{}".format(self.repo_owner, self.repo_name)

        try:
            token = self.gh.authorize(username, password, scopes=('public_repo'), note=token_note)
        except Exception as e:
            if self._authorization_description_already_exists(e):
                # try again with a new description
                if create_duplicate:
                    token_note += " " + datetime.datetime.utcnow().isoformat()
                    token = self.gh.authorize(username, password, scopes=('public_repo'), note=token_note)
                else:
                    raise Exception('repo token already exists for {}'.format(self.repo_slug))
            else:
                raise e

        self._repo_token = token.token
        return self._repo_token
    
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
        repo_public_key = serialization.load_pem_public_key(repo_public_key_text.encode('utf-8'),
                                                            backend=default_backend())

        ciphertext = repo_public_key.encrypt(
         token_string,
         padding.PKCS1v15()
        )

        return base64.b64encode(ciphertext)
    
    
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
    
        encrypted_key = self.travis_encrypt(self.repo_token())
        
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
        
    def run(self, from_repo_owner='GITenberg', 
                                      create_duplicate_token=False,
                                      update_repo_token_file=True,
                                      load_repo_token=True):
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
