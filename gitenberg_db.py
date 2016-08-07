import sqlalchemy

from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import os

import arrow

import io, csv
from itertools import islice

Base = declarative_base()

class Repo(Base):
    __tablename__ = 'repos'
        
    gutenberg_id = Column(Integer, primary_key=True)
    updated = Column(String)
    repo_name = Column(String)
    repo_owner = Column(String)
    datebuilt = Column(Integer)
    version = Column(String)
    ebooks_in_release_count = Column(Integer)
    last_build_id = Column(Integer)
    last_build_state = Column(String)
    buildable = Column(Boolean)
    has_metadata = Column(Boolean)
    has_source = Column(Boolean)
    
    metadata_written = Column(String)
    
    def __repr__(self):
        return "<Repo(repo_owner='%s' repo_name='%s')>" % (
                             self.repo_owner, self.repo_name)

def create_RepoTable(fname):

    #if os.path.exists(fname):
    #    os.remove(fname)

    engine = create_engine('sqlite:///{}'.format(fname), echo=False)
    Base.metadata.create_all(engine, checkfirst=True)
    
    return engine


def create_session(fname):
	engine = create_engine('sqlite:///{}'.format(fname), echo=False)

	Session = sessionmaker(bind=engine)
	session = Session()

	return session

def init_repos(session, repo_owner='GITenberg', max_repos=None):

    REPO_LIST_PATH = "/Users/raymondyee/C/src/gitberg/build/lib/gitenberg/data/GITenberg_repo_list.tsv"
    PAGE_SIZE = 50
    PER_PAGE = 500
    
    with io.open(REPO_LIST_PATH, mode='r', encoding='UTF-8') as f:
        s = f.read()

    repos = [row.split("\t") for row in s.split("\n") if len(row.split("\t")) == 2]
 
    for (i, page) in enumerate(grouper(islice(repos ,max_repos), PAGE_SIZE)):

        page_of_repos = []

        for repo in page:
            repo_obj = Repo(gutenberg_id=repo[0], 
                            repo_name=repo[1], 
                            repo_owner=repo_owner, 
                            updated=arrow.now().isoformat()
                           )
            
            page_of_repos.append(repo_obj)

        try:    
            session.add_all(page_of_repos)
            session.commit()
        except Exception, e:
            print (e)
            session.rollback()
            break

    session.commit()