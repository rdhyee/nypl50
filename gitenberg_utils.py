__all__ = ['GitenbergJob']

# import github3.py
import arrow
import github3
from gitenberg import metadata
import requests
import semantic_version
import yaml


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


