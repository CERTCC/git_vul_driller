#!/usr/bin/env python
"""
file: basic_driller
author: adh
created_at: 7/13/21 1:04 PM
"""
import git

# from memory_profiler import profile

from pydriller import Repository
import gc
import random

from git_vul_driller.patterns import PATTERN, normalize
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level
# add the handlers to the logger
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# ch.setFormatter(formatter)
logger.addHandler(ch)


# @profile
def main(repo_path, start_tag=None):
    repo = git.Repo(repo_path)
    # populate a set of tags once so we can speed up membership checks
    tags = set([t.name for t in repo.tags])

    # figure out which commits we need to process
    if (start_tag is None) or (start_tag not in tags):
        rm = Repository(path_to_repo=repo_path, order="date-order")
    else:
        rm = Repository(path_to_repo=repo_path, from_tag=start_tag, order="date-order")

    # we know which commits to process.
    # ok, let's start
    last_commit = None
    for commit in rm.traverse_commits():
        collected = False

        # print(f"=> Processing commit {commit.hash}")
        # remember it for when the loop ends
        last_commit = commit.hash

        # check the commit message
        matches = set()
        for m in PATTERN.findall(commit.msg):
            m = normalize(m)
            if m not in tags:
                tagit(commit.hash, m, repo)
                tags.add(m)

        # check the adds
        for mod in commit.modified_files:
            adds = mod.diff_parsed["added"]
            for (line_no, line_str) in adds:
                for m in PATTERN.findall(line_str):
                    m = normalize(m)
                    if m not in tags:
                        tagit(commit.hash, m, repo)
                        tags.add(m)
                if random.random() < 0.05:
                    gc.collect()
            if not collected:
                gc.collect()
                collected = True
        if not collected:
            gc.collect()

    # remember where we left off for next time
    if start_tag is not None:
        print(f" + Tagging {last_commit} as {start_tag}")
        repo.create_tag(start_tag, ref=(last_commit), force=True)


def tagit(chash, m, repo):
    # but create any new ones
    print(f" + Tagging {chash} with {m}")
    repo.create_tag(m, ref=chash)
    # avoid duplication in the same run


if __name__ == "__main__":
    repo_path = "data/sources/metasploit-framework"
    # start_tag = "last_run"
    start_tag = "test_run"
    # start_tag = None

    from datetime import datetime

    startTime = datetime.now()

    main(repo_path, start_tag)

    # Python 3:
    print(datetime.now() - startTime)
