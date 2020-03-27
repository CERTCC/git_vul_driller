#!/usr/bin/env python
"""
file: repo_drill
author: adh
created_at: 3/27/20 11:45 AM
"""
from pydriller import RepositoryMining, GitRepository
from pprint import pprint
from multiprocessing import Pool
from datetime import datetime
from git_repo_crawler.patterns import PATTERN, normalize
import pandas as pd

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


def process_chunk(chunk):
    for commit in chunk:
        yield process_commit(commit)


def process_modifications(mod):
    mod_data = {k: getattr(mod, k, None) for k in modification_fields}

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
    return matches


def process_commit(commit):
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
    df = pd.DataFrame(commits)
    df["author_date"] = pd.to_datetime(df["author_date"], utc=True)
    df["committer_date"] = pd.to_datetime(df["committer_date"], utc=True)

    return df


def process_repo(repo_path):
    miner = RepositoryMining(repo_path, since=datetime(2020, 1, 1, 0, 0, 0))
    iterable = miner.traverse_commits()

    commits = []
    for commit in iterable:
        data = process_commit(commit)

        if len(data["vul_ids"]):
            del data["modifications"]
            commits.extend(invert_refs(data))

    return commits_to_df(commits)


def main():

    df = process_repo(repo)
    df.sort_values(by="author_date", ascending=True, inplace=True)
    df.drop_duplicates(subset=["reference", "fpath"], keep="first", inplace=True)

    print(f"Found {len(df)} commits")

    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 10)

    cve_rows = df[df["reference"].apply(lambda x: x.lower().startswith("cve-"))]
    print(cve_rows)


if __name__ == "__main__":
    main()
