#!/usr/bin/env python
"""
file: repo_drill
author: adh
created_at: 3/27/20 11:45 AM
"""
from pydriller import RepositoryMining
from datetime import datetime

from git_repo_crawler.config import read_config
from git_repo_crawler.data_handler import dump_json, dump_csv
from git_repo_crawler.patterns import PATTERN, normalize
import pandas as pd
import logging
import git
import os
import argparse
from functools import partial
import multiprocessing as mp

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
DUMP_INTERVAL = 500

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


def pull_repo(repo_path, clone_url):
    repo = git.Repo(repo_path)

    try:
        origin = repo.remotes.origin
    except AttributeError as e:
        origin = repo.create_remote(name="origin", url=clone_url)

    repo.heads.master.set_tracking_branch(origin.refs.master)

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
    origin.pull()


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


def _commit_handler(commit_hash=None, repo_path=None):
    # create a one-shot repository miner for this commit
    try:
        rm = RepositoryMining(path_to_repo=repo_path, single=commit_hash)
    except OSError as e:
        PID = os.getpid()
        logger.error(f"{PID} {e}")
        raise

    # RM uses GitPython, and GitPython wants to use a config file lock in case we are going to make changes
    # But in our case we know we're not. So we have to add some extra handling to get rid of the file locks
    # in order to proceed. Yes, there is an inherent race condition here, but in practical terms it eventually works.
    while True:
        try:
            # although this is a for loop, we only get a single commit out of it
            for commit in rm.traverse_commits():
                data = process_commit(commit)
            break
        except OSError as e:
            # when GitPython can't get a config file lock, it throws an OSError
            lockfile = os.path.join(repo_path, ".git/config.lock")
            try:
                os.remove(lockfile)
            except OSError as e:
                pass
                # print(f"Caught OSError: {e}")

    return data


def _dh(data):
    refined = []
    if len(data["vul_ids"]):
        # at this point, we don't need to keep every single line that changed
        # we already know which vul ids are mentioned
        del data["modifications"]

        new_data = invert_refs(data)
        refined.extend(new_data)

    return refined


def main():
    # parse args
    args = _parse_args()

    # read config
    cfg = read_config(args.cfgpath)

    logger.info("Create data and output dirs if needed")
    # make data and output dirs if needed
    os.makedirs(cfg["work_path"], exist_ok=True)
    os.makedirs(cfg["output_path"], exist_ok=True)

    # clone or refresh repo
    clone_or_pull_repo(cfg)

    # get list of commits
    logger.info(f"Get list of commit hashes from {cfg['repo_path']}")
    ch, commit_hashes = get_commit_hashes_from_repo(cfg["repo_path"])

    commit_handler = partial(_commit_handler, repo_path=cfg["repo_path"])

    logger.info(f"Processing {len(commit_hashes)} commits...")
    pool = mp.Pool()
    commit_data = pool.imap_unordered(
        func=commit_handler, iterable=commit_hashes, chunksize=20
    )
    results2 = pool.imap_unordered(func=_dh, iterable=commit_data)

    data = []
    for r in results2:
        data.extend(r)

    logger.info("Create dataframe from commits")
    df = commits_to_df(data)

    fname_base = "vul_sightings"
    json_fname = f"{fname_base}_{ch}.json"
    json_file = os.path.join(cfg["output_path"], json_fname)

    logger.info("Dumping data to JSON")
    dump_json(df, json_file)

    logger.info("Done")


def get_commit_hashes_from_repo(repo_path):
    repo = git.Repo(repo_path)
    commit_hashes = [c.hexsha for c in repo.iter_commits()]
    head_commit_hash = repo.head.commit.hexsha
    return head_commit_hash, commit_hashes


def clone_or_pull_repo(cfg):
    if not os.path.exists(cfg["repo_path"]):
        logger.info(f"No repo found at {cfg['repo_path']}")
        logger.info(f"Cloning from {cfg['clone_url']}")

        git.Repo.clone_from(url=cfg["clone_url"], to_path=cfg["repo_path"])
    else:
        pull_repo(cfg["repo_path"], cfg["clone_url"])


if __name__ == "__main__":
    main()
