# Tokens used for GitHub and Travis

[The Travis CI Blog: Token, Token, Token](https://blog.travis-ci.com/2013-01-28-token-token-token)  describe several types of tokens:

* GitHub Token
* (Travis) Access Token
* Travis [Profile] Token 

In addition: there are per repo_token

Looking at parameters in [nypl50/gitenberg_utils.py at 9fe5e01bd1116ffb5106be6ac8b241d83c652ece · rdhyee/nypl50](https://github.com/rdhyee/nypl50/blob/9fe5e01bd1116ffb5106be6ac8b241d83c652ece/gitenberg_utils.py#L418-L420). 


```
class GitenbergTravisJob(GitenbergJob):
    def __init__(self, username, password, repo_name, repo_owner,
               update_travis_commit_msg,
               tag_commit_message, github_token=None, access_token=None, repo_token=None):

```
* `username`, `password`: GitHub username, password
* `github_token`: optional GitHub authorization token for use with travis with [certain permissions](https://github.com/rdhyee/nypl50/blob/9fe5e01bd1116ffb5106be6ac8b241d83c652ece/gitenberg_utils.py#L458-L460).
* `access_token`: (Travis) Access Token


Given a GitHub username, password you can create and save a `github_token` and (travis) `access_token` for future use.  One way:

```Python
# to compute a GITENBERG_GITHUB_TOKEN and GITENBERG_TRAVIS_ACCESS_TOKEN to use
# username, password are GitHub username, password

from github_settings import (
                             username, password
                            )

from gitenberg_utils import GitenbergTravisJob
                             
# could be any of the Gitenberg repos for repo_name
gtj = GitenbergTravisJob(username=username, password=password, repo_name="Moby-Dick--Or-The-Whale_2701",
                         repo_owner='GITenberg', update_travis_commit_msg='', tag_commit_message='')

# compute GITENBERG_GITHUB_TOKEN
print ("GitHub token:", gtj.github_token())

# compute GITENBERG_TRAVIS_ACCESS_TOKEN
t = gtj.travis
print ("Travis access token:", t._session.headers['Authorization'].split()[1])
```


I ran into a strange problem when I don't provide an `access_token`.  It seems that the process of obtaining an Travis access token can use up a lot of calls to the GitHub API. If you use a GitHub key that has already been fed to travis, there's no heavy us of GitHub API calls.  You can see how many calls you have left in the current period (limits reset hourly).

`gtj.gh.rate_limit()`.

Once you compute a GitHub token and a Travis access token, save them -- for example, in `github_settings.py` for future use:


```Python
username = "FILL IN"  # e., username = "rdhyee-GITenberg"
password = "FILL IN"

# 
GITENBERG_GITHUB_TOKEN = "FILL IN"
GITENBERG_TRAVIS_ACCESS_TOKEN = "FILL IN"
```

