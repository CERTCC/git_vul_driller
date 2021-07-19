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
def main(repo_path, tag=None):
    repo = git.Repo(repo_path)
    # populate a set of tags once so we can speed up membership checks
    tags = set([t.name for t in repo.tags])

    start_tag = None
    if tag in tags:
        start_tag = tag

    new_tags = set()
    # we know which commits to process.
    # ok, let's start
    last_commit = None
    for c in repo.iter_commits(rev=f"{start_tag}..HEAD", reverse=True):
        # for commit in rm.traverse_commits():
        collected = False

        chash = c.hexsha

        print(f"=> Processing commit {chash}")
        # remember it for when the loop ends
        last_commit = chash

        # PyDriller is super heavy on memory usage in a loop
        # so we're going to only create it when we need it
        rm = Repository(path_to_repo=repo_path, single=chash)
        commit = None
        for _commit in rm.traverse_commits():
            commit = _commit
        del rm

        # check the commit message
        matches = set()
        for m in PATTERN.findall(commit.msg):
            m = normalize(m)
            if m not in tags:
                tagit(commit.hash, m, repo)
                tags.add(m)
                new_tags.add(m)

        # check the adds
        counter = 0
        for mod in commit.modified_files:
            for (line_no, line_str) in mod.diff_parsed["added"]:
                for m in PATTERN.findall(line_str):
                    # counter += 1
                    m = normalize(m)
                    if m not in tags:
                        tagit(commit.hash, m, repo)
                        tags.add(m)
                        new_tags.add(m)

    # write out new tags to a file
    tag_file = "new_tags.txt"
    with open(tag_file, "w") as fp:
        fp.write("\n".join(new_tags))
        fp.write("\n")

    # remember where we left off for next time
    if last_commit is not None and tag is not None:
        print(f" + Tagging {last_commit} as {tag}")
        repo.create_tag(tag, ref=(last_commit), force=True)


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
