#!/usr/bin/env python
"""
file: repo_drill_common
author: adh
created_at: 4/16/20 9:29 AM
"""
import argparse
import multiprocessing as mp
import os
from datetime import datetime
from functools import partial

import git
import pandas as pd
from pydriller import RepositoryMining

from git_repo_crawler.config import read_config
from git_repo_crawler.data_handler import dump_json

from git_repo_crawler.patterns import PATTERN, normalize
import logging

# suppress pydriller's verbose logging
logging.getLogger("pydriller.repository_mining").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
lock = mp.Lock()
LOG_INTERVAL = 200
DUMP_INTERVAL = 500
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

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")


def setup_file_logger(logfile):
    # create file handler which logs even debug messages
    fh = logging.FileHandler(filename=logfile, mode="w")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)


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

    commit_data["data_source"] = "exploitdb_git"

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


def commit_handler(commit_hash=None, repo_path=None):
    # RepositoryMining uses a pydriller.GitRepository object.
    # in turn that GitRepository object attempts to set a file based
    # config.lock on the .git/config file in the repository when the
    # object is initialized. When running this function in a parallel process, we
    # run into a problem where all the processes are trying to create that lock at
    # the same time. So we need to use our own multiprocessing.Lock here to avoid
    # the locking failure.
    commit = None
    with lock:
        rm = RepositoryMining(path_to_repo=repo_path, single=commit_hash)
        # we're doing a single commit, but traverse_commits is still a generator
        # so this for loop is just a formality
        for _commit in rm.traverse_commits():
            commit = _commit

    assert commit is not None

    # we only need the lock while we're using the repository miner. Once we have
    # our commit we can go back to full parallel operation.
    data = process_commit(commit)
    return data


def dh(data):
    refined = []
    if len(data["vul_ids"]):
        # at this point, we don't need to keep every single line that changed
        # we already know which vul ids are mentioned
        del data["modifications"]

        new_data = invert_refs(data)
        refined.extend(new_data)

    return refined


def get_commit_hashes_from_repo(repo_path):
    repo = git.Repo(repo_path)
    commit_hashes = [c.hexsha for c in repo.iter_commits()]
    head_commit_hash = repo.head.commit.hexsha
    return head_commit_hash, commit_hashes


def clone_or_pull_repo(repo_path, clone_url):
    if not os.path.exists(repo_path):
        logger.info(f"No repo found at {repo_path}")
        logger.info(f"Cloning from {clone_url}")

        git.Repo.clone_from(url=clone_url, to_path=repo_path)
    else:
        pull_repo(repo_path, clone_url)


def parse_args(defaults):
    logger.debug("Parsing command line args")
    parser = argparse.ArgumentParser(
        description="Extract vulnerability IDs out of a git repository"
    )
    parser.add_argument(
        "--config",
        dest="cfgpath",
        action="store",
        type=str,
        default=defaults["cfgpath"],
        help="path to config_metasploit.yaml",
    )

    args = parser.parse_args()

    for k, v in vars(args).items():
        logger.debug(f"... {k}: {v}")
    return args


def main(defaults):
    # parse args
    args = parse_args(defaults)

    # read config
    cfg = read_config(args.cfgpath)

    setup_file_logger(cfg["logfile"])

    logger.info("Create data and output dirs if needed")
    # make data and output dirs if needed
    os.makedirs(cfg["work_path"], exist_ok=True)
    os.makedirs(cfg["output_path"], exist_ok=True)

    # clone or refresh repo
    clone_or_pull_repo(cfg["repo_path"], cfg["clone_url"])

    # get list of commits
    logger.info(f"Get list of commit hashes from {cfg['repo_path']}")
    ch, commit_hashes = get_commit_hashes_from_repo(cfg["repo_path"])

    _commit_handler = partial(commit_handler, repo_path=cfg["repo_path"])

    logger.info(f"Processing {len(commit_hashes)} commits...")

    pool = mp.Pool()
    logger.info(f"Poolsize: {len(pool._pool)}")

    commit_data = pool.imap_unordered(func=_commit_handler, iterable=commit_hashes)
    results2 = pool.imap_unordered(func=dh, iterable=commit_data)

    data = []
    for r in results2:
        data.extend(r)

    logger.info("Create dataframe from commits")
    df = commits_to_df(data)

    if len(df) < 1:
        logger.warning("DataFrame appears empty!")

    fname_base = cfg["outfile_basename"]
    json_fname = f"{fname_base}_{ch}.json"
    json_file = os.path.join(cfg["output_path"], json_fname)

    logger.info("Dumping data to JSON")
    dump_json(df, json_file)

    logger.info("Done")


if __name__ == "__main__":
    main()
