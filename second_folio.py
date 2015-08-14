
import glob
import os
import shutil
import re
import sys
import time

import requests
import sh
import pexpect
import yaml
import jinja2

from gitenberg import metadata


REPOS_LIST_URL = "https://raw.githubusercontent.com/gitenberg-dev/Second-Folio/master/list_of_repos.txt"
GITENBERG_DIR = "/Users/raymondyee/C/src/gitenberg/"
TRAVIS_TEMPLATE_URL = "https://github.com/gitenberg-dev/templates/raw/master/.travis.yml"


def git_pull(repo):
    sh.cd(os.path.join(GITENBERG_DIR, repo))
    sh.git("pull")

def repos_list():
    r = requests.get(REPOS_LIST_URL)
    return r.content.strip().split("\n")


def travis_template():
    r = requests.get(TRAVIS_TEMPLATE_URL)
    return r.content


def apply_to_repos(action, args=None, kwargs=None, repos=None):

    if repos is None:
        repos = all_repos
    
    if args is None:
        args = []
        
    if kwargs is None:
        kwargs = {}
        
    for repo in repos:
        try:
            result = action (repo, *args, **kwargs)
        except Exception as e:
            result = e
        yield result
        
def git_mv_asciidoc(repo):
    
    """
    git mv the asciidoc file to book.asciidoc if it's the only asciidoc in root dir
    """
    
    sh.cd(os.path.join(GITENBERG_DIR, repo))
    asciidocs =  glob.glob("*.asciidoc")
    if len(asciidocs) == 1 and asciidocs[0] <> "book.asciidoc":
        sh.git.mv(asciidocs[0], "book.asciidoc")
        return True
    else:
        return False

    
def git_commit_mv_asciidoc(repo):
    
    sh.cd(os.path.join(GITENBERG_DIR, repo))
    
    try:
        if os.path.exists(os.path.join(GITENBERG_DIR, repo, "book.asciidoc")):
            sh.git.add("book.asciidoc")
            try:
                sh.git.commit("-m", "rename asciidoc to book.asciidoc")
            except:
                pass
            sh.git.push()
            return True
        else:
            return False
    except Exception as e:
        return e
    
def repo_is_buildable(repo):
    book_path = os.path.join(GITENBERG_DIR, repo, "book.asciidoc")
    cover_path = os.path.join(GITENBERG_DIR, repo, "cover.jpg")
    metadata_path = os.path.join(GITENBERG_DIR, repo, "metadata.yaml")
    
    return (os.path.exists(book_path) and 
            os.path.exists(cover_path) and
            os.path.exists(metadata_path))

def has_travis_with_gitenberg_build(repo):
    travis_path = os.path.join(GITENBERG_DIR, repo, ".travis.yml")
    if not os.path.exists(travis_path):
        return False
    else:
        # read the file
        try:
            y = yaml.load(open(travis_path).read())
            repo = y['deploy']['on']['repo'] 
            if repo.startswith("GITenberg"):
                return True
            else:
                return False
        except Exception as e:
            return False
            
    
def travis_setup_releases(repo, path, username, password, file_to_upload):

    cmd = """travis setup releases --force --no-interactive"""
    child = pexpect.spawn(cmd, cwd=path)
    
    #child.logfile = sys.stdout

    child.expect("Username")
    child.sendline(username)

    child.expect("Password for")
    child.sendline(password)

    child.expect("File to Upload")
    child.sendline(file_to_upload)

    child.expect("Deploy only")
    child.sendline("yes")

    child.expect("Encrypt API")
    child.sendline("yes")
    
def apply_travis(repo,username, password, overwrite_travis=False):
    sh.cd(os.path.join(GITENBERG_DIR, repo))
    
    metadata_path = os.path.join(GITENBERG_DIR, repo, "metadata.yaml")
    travis_path = os.path.join(GITENBERG_DIR, repo, ".travis.yml")
    
    if os.path.exists(metadata_path):
        md = metadata.pandata.Pandata(os.path.join(GITENBERG_DIR, repo, "metadata.yaml"))
        repo_name = md.metadata.get("_repo")
        # may need a better way to create epub titles
        epub_title = slugify(md.metadata.get("title"))
        encrypted_key = "xxxx"  # looking for a replacement
        
        # write the travis file
        if not os.path.exists(".travis.yml") or overwrite_travis:
            with open(".travis.yml", "w") as f:
                travis_source = travis_template.render(encrypted_key=encrypted_key, epub_title=epub_title, repo_name=repo_name)
                f.write(travis_source)
        
           # run travis setup releases to get an encrypted key
            
            travis_setup_releases(repo, os.path.join(GITENBERG_DIR, repo), 
                                  username, password, "{}.epub".format(epub_title))
        

            time.sleep(5) # wait to make sure the token gets written
            
            # now read off the encrypted key and use it to rewrite the travis file
            y = yaml.load(open(travis_path).read())
            encrypted_key = y['deploy']['api_key']['secure']
            print (encrypted_key)
            
            if encrypted_key <> "xxxx":
                with open(".travis.yml", "w") as f:
                    travis_source = travis_template.render(encrypted_key=encrypted_key, epub_title=epub_title, repo_name=repo_name)
                    f.write(travis_source)
                        
                return True
            else:
                return False
        else:
            return False
    else:
        return False
    
def finish_travis(repo):
    
    sh.cd(os.path.join(GITENBERG_DIR, repo))

    metadata_path = os.path.join(GITENBERG_DIR, repo, "metadata.yaml")
    travis_path = os.path.join(GITENBERG_DIR, repo, ".travis.yml")
    
    try:
        sh.travis.enable("--no-interactive")
    except:
        pass
    
    sh.git.add(".travis.yml")
    sh.git.commit("-m", "add .travis.yml", _ok_code=[0,1])
    sh.git.tag("0.0.1", _ok_code=[0,1])
    sh.git.push("origin", "master", "--tags", _ok_code=[0,1])
    
    return True
    
# http://stackoverflow.com/a/295466

def slugify(value):
    """
    Normalizes string, removes non-alpha characters,
    and converts spaces to hyphens.
    """
    import unicodedata
    # assume that strings are ascii
    if isinstance(value, str):
        value = value.decode('ascii')
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore')
    # keep case
    #value = unicode(re.sub('[^\w\s-]', '', value).strip().lower())
    value = unicode(re.sub('[^\w\s-]', '', value).strip())
    value = unicode(re.sub('[-\s]+', '-', value))
    
    return value

    
def _travis_setup_releases_0():
    """
    a failed attempt 
    """
    sh.cd("/Users/raymondyee/C/src/gitenberg/Don-Quixote_996")
    #sh.ls("-1", "junk", _out=process_output, _err=process_output)
    #sh.travis.status( "--no-interactive", _ok_code=[0,1], _out=process_output, _err=process_output)
    #sh.travis.status(_timeout=10, _ok_code=[0,1], _out=process_output, _err=process_output)
    p = sh.travis.setup.releases("--no-interactive", "--force",
                             _timeout=5, _ok_code=[0,1], _out=process_output, _err=process_output,_tty_in=True, _out_bufsize=0)
    p.wait()
    
all_repos = repos_list()
travis_template = jinja2.Template(travis_template())

