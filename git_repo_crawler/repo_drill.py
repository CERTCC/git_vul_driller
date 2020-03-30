#!/usr/bin/env python
"""
file: repo_drill
author: adh
created_at: 3/27/20 11:45 AM
"""
from pydriller import RepositoryMining, GitRepository
from datetime import datetime
from git_repo_crawler.patterns import PATTERN, normalize
import pandas as pd
import logging
import git

# set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler(filename="../log/repo_drill.log", mode="w")
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)

LOG_INTERVAL = 200

# how often to refresh the git repo, in seconds
REFRESH_AFTER_SECONDS = 3600 * 4

commit_fields = [
    "hash",
    "msg",
    "author",
    "author_date",
    "author_timezone",
    "committer",
    "committer_date",
    "committer_timezone",
    "branches",
    "in_main_branch",
    "merge",
    "modifications",
    "parents",
    "project_name",
    "project_path",
]

modification_fields = [
    "old_path",
    "new_path",
    "change_type",
    "diff_parsed",
    "added",
    "removed",
]

repo = "../data/metasploit-framework"


def process_modifications(mod):
    mod_data = {k: getattr(mod, k, None) for k in modification_fields}

    # pull the actual changes out of the parsed diff
    mod_data["added"] = mod_data["diff_parsed"]["added"]
    mod_data["deleted"] = mod_data["diff_parsed"]["deleted"]
    del mod_data["diff_parsed"]

    return mod_data


def find_vul_ids(commit_data):
    c = commit_data

    matches = set()
    # check in msg
    for m in PATTERN.findall(c["msg"]):
        m = normalize(m)
        rec = (m, None)
        matches.add(rec)

    # check in adds
    for mod in c["modifications"]:
        for a in mod["added"]:
            (line_num, add) = a
            for m in PATTERN.findall(add):
                m = normalize(m)
                rec = (m, mod["new_path"])
                matches.add(rec)

    if len(matches):
        logger.debug(f"matched {len(matches)} ids")
        for m in matches:
            logger.debug(f"match: {m}")

    # note we don't bother to check in the deletes because we don't really care
    # if the string disappeared

    return matches


def process_commit(commit):
    logger.debug(f"processing commit: {commit.hash}")
    commit_data = {k: getattr(commit, k, None) for k in commit_fields}

    commit_data["modifications"] = [
        process_modifications(m) for m in commit_data["modifications"]
    ]

    commit_data["vul_ids"] = list(find_vul_ids(commit_data))

    # bring developer data to the surface
    for f in ["author", "committer"]:
        developer = commit_data[f]
        for k in ["name", "email"]:
            key = f"{f}_{k}"
            commit_data[key] = getattr(developer, k, None)
        del commit_data[f]

    return commit_data


def invert_refs(record):
    logger.debug("inverting references")
    refs = record.get("vul_ids")
    fields = [k for k in record.keys() if k != "vul_ids"]

    inverted = []
    for vid, fpath in refs:
        new_rec = {k: record[k] for k in fields}
        new_rec["reference"] = vid
        new_rec["fpath"] = fpath
        inverted.append(new_rec)
    return inverted


def commits_to_df(commits):
    logger.info("creating dataframe")
    df = pd.DataFrame(commits)
    df["author_date"] = pd.to_datetime(df["author_date"], utc=True)
    df["committer_date"] = pd.to_datetime(df["committer_date"], utc=True)

    return df


def process_repo(repo_path):

    logger.info(f"Processing repo {repo_path}")

    miner = RepositoryMining(repo_path, since=datetime(2019, 10, 1, 0, 0, 0))
    iterable = miner.traverse_commits()

    commits = []

    for i, commit in enumerate(iterable):
        data = process_commit(commit)

        if (i % LOG_INTERVAL) == 0:
            logger.info(f"... {i} commits processed ({len(commits)} records extracted)")

        if len(data["vul_ids"]):
            # at this point, we don't need to keep every single line that changed
            # we already know which vul ids are mentioned
            del data["modifications"]

            commits.extend(invert_refs(data))

    return commits_to_df(commits)


def main():

    df = process_repo(repo)
    logger.info("Done")

    # keep only the first time a reference / file path pair appear
    df.sort_values(by="author_date", ascending=True, inplace=True)
    df.drop_duplicates(subset=["reference", "fpath"], keep="first", inplace=True)

    print(f"Found {len(df)} commits")

    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 10)

    cve_rows = df[df["reference"].apply(lambda x: x.lower().startswith("cve-"))]
    print(cve_rows)


if __name__ == "__main__":
    main()
