#!/usr/bin/env python
"""
file: basic_driller
author: adh
created_at: 7/13/21 1:04 PM
"""
import git

from pydriller import Repository

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
        print(f"=> Processing commit {commit.hash}")
        # remember it for when the loop ends
        last_commit = commit.hash

        # check the commit message
        matches = set()
        for m in PATTERN.findall(commit.msg):
            m = normalize(m)
            matches.add(m)

        # check the adds
        for mod in commit.modified_files:
            n_adds = len(mod.diff_parsed["added"])
            if n_adds < 1:
                continue

            for (line_no, line_str) in mod.diff_parsed["added"]:
                for m in PATTERN.findall(line_str):
                    m = normalize(m)
                    matches.add(m)

        # tag the matches
        for m in matches:
            # don't duplicate existing tags
            if m in tags:
                print(f" - Tag {m} already exists at {repo.commit(m)}")
                continue

            # but create any new ones
            print(f" + Tagging {commit.hash} with {m}")
            repo.create_tag(m, ref=commit.hash)

    # remember where we left off for next time
    if start_tag is not None:
        print(f" + Tagging {last_commit} as {start_tag}")
        repo.create_tag(start_tag, ref=(last_commit), force=True)


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
