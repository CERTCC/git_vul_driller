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
import os
import yaml
import argparse


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

# how many commits to process before logging?
LOG_INTERVAL = 200

# how many records to construct before dumping data out?
DUMP_INTERVAL = 200

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
        rec = (m, "COMMIT_MSG")
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

    commit_data["data_source"] = "metasploit_git"

    commit_data["modifications"] = [
        process_modifications(m) for m in commit_data["modifications"]
    ]

    commit_data["vul_ids"] = list(find_vul_ids(commit_data))

    # truncate commit messages
    # slice at first newline
    commit_data["msg"] = commit_data["msg"].split("\n")[0]
    # truncate to 80 char max
    commit_data["msg"] = commit_data["msg"][:80]

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
    logger.debug("creating dataframe")
    df = pd.DataFrame(commits)
    df["author_date"] = pd.to_datetime(df["author_date"], utc=True)
    df["committer_date"] = pd.to_datetime(df["committer_date"], utc=True)

    return df


def pull_repo(repo_path):
    repo = git.Repo(repo_path)

    # see if it's time to refresh yet
    commit = repo.head.commit
    last_update = commit.committed_datetime.timestamp()
    now = datetime.now().timestamp()
    time_since = now - last_update

    if time_since < REFRESH_AFTER_SECONDS:
        # not time to refresh yet
        logger.debug(
            f"Skipping pull ({time_since:.0f} of {REFRESH_AFTER_SECONDS} elapsed)"
        )
        return

    logger.info(f"Pulling {repo_path} from origin ({time_since:.0f} last refresh)")
    # if you got here, it's time to refresh
    o = repo.remotes.origin
    o.pull()


def dump_csv(commits, csv_file):
    logger.info(f"writing data to {csv_file}")
    df = commits_to_df(commits)
    df.to_csv(path_or_buf=csv_file, index=False)
    return df


def process_repo(repo_path):

    logger.info(f"Processing repo {repo_path}")

    miner = RepositoryMining(repo_path, since=datetime(2018, 1, 1, 0, 0, 0))
    iterable = miner.traverse_commits()

    commits = []
    _df = None
    record_count = 0

    for i, commit in enumerate(iterable):
        data = process_commit(commit)

        if (i % LOG_INTERVAL) == 0:
            logger.info(f"... {i} commits processed ({record_count} records extracted)")

        if len(data["vul_ids"]):
            # at this point, we don't need to keep every single line that changed
            # we already know which vul ids are mentioned
            del data["modifications"]

            new_commit_records = invert_refs(data)
            record_count += len(new_commit_records)
            commits.extend(new_commit_records)

        if len(commits) >= DUMP_INTERVAL:
            csv_file = f"../output/vul_sightings_{commit.hash}.csv"
            df = dump_csv(commits, csv_file)
            commits = []

    if _df is None:
        _df = df
    else:
        _df = _df.append(df)

    return df


def _read_config(cfg_path):
    logger.debug(f"Reading config from {cfg_path}")
    with open(cfg_path, "r") as fp:
        cfg = yaml.safe_load(fp)

    cfg["work_path"] = os.path.abspath(os.path.expanduser(cfg["work_path"]))
    cfg["repo_path"] = os.path.join(cfg["work_path"], cfg["repo_path"])

    for k, v in cfg.items():
        logger.debug(f"... {k} = {v}")

    return cfg


def _parse_args():
    logger.debug("Parsing command line args")
    parser = argparse.ArgumentParser(
        description="Extract vulnerability IDs out of Metasploit Framework"
    )
    parser.add_argument(
        "--config",
        dest="cfgpath",
        action="store",
        type=str,
        default="../config.yaml",
        help="path to config.yaml",
    )

    args = parser.parse_args()

    for k, v in vars(args).items():
        logger.debug(f"... {k}: {v}")
    return args


def main():
    # parse args
    args = _parse_args()

    # read config
    cfg = _read_config(args.cfgpath)

    # make data dir if needed
    os.makedirs(cfg["work_path"], exist_ok=True)

    # clone or refresh repo
    clone_or_pull_repo(cfg)

    # process repo
    df = process_repo(cfg["repo_path"])

    logger.info("Done")

    # keep only the first time a reference / file path pair appear
    df.sort_values(by="author_date", ascending=True, inplace=True)
    df.drop_duplicates(subset=["reference", "fpath"], keep="first", inplace=True)

    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 10)

    cve_rows = df[df["reference"].apply(lambda x: x.lower().startswith("cve-"))]
    print(cve_rows)


def clone_or_pull_repo(cfg):
    if not os.path.exists(cfg["repo_path"]):
        logger.info(f"No repo found at {cfg['repo_path']}")
        logger.info(f"Cloning from {cfg['clone_url']}")

        git.Repo.clone_from(url=cfg["clone_url"], to_path=cfg["repo_path"])
    else:
        pull_repo(cfg["repo_path"])


if __name__ == "__main__":
    main()
