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
import glob

import git
import pandas as pd
from pydriller import RepositoryMining

from git_vul_driller.config import read_config
from git_vul_driller.data_handler import dump_json, dump_csv

from git_vul_driller.patterns import PATTERN, normalize
import logging

# suppress pydriller's verbose logging
logging.getLogger("pydriller.repository_mining").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# lock = mp.Lock()
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


def process_commit(commit, clone_url=None):
    logger.debug(f"processing commit: {commit.hash}")

    commit_data = {k: getattr(commit, k, None) for k in commit_fields}

    commit_data["data_source"] = clone_url

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


def commit_handler(commit_hash=None, repo_path=None, clone_url=None):
    # RepositoryMining uses a pydriller.GitRepository object.
    # in turn that GitRepository object attempts to set a file based
    # config.lock on the .git/config file in the repository when the
    # object is initialized. When running this function in a parallel process, we
    # run into a problem where all the processes are trying to create that lock at
    # the same time. So we need to use our own multiprocessing.Lock here to avoid
    # the locking failure.
    commit = None
    lock.acquire()
    rm = RepositoryMining(path_to_repo=repo_path, single=commit_hash)
    # we're doing a single commit, but traverse_commits is still a generator
    # so this for loop is just a formality
    for _commit in list(rm.traverse_commits()):
        commit = _commit
    lock.release()

    assert commit is not None

    # we only need the lock while we're using the repository miner. Once we have
    # our commit we can go back to full parallel operation.
    data = process_commit(commit, clone_url=clone_url)
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


def get_commit_hashes_from_repo(repo_path, last_=None):

    repo = git.Repo(repo_path)

    if last_ is not None:
        commit_hashes = [c.hexsha for c in repo.iter_commits(rev=f"{last_}..HEAD")]
    else:
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


def setup_dirs(cfg):
    cfgpaths = ["work_path", "output_path", "log_path"]
    for key in cfgpaths:
        path = cfg.get(key)
        logger.debug(f"Check/create {key}: {path}")

        os.makedirs(path, exist_ok=True)

        assert os.path.isdir(path), f"Path {path} does not exist"


def write_data(df, fname_base, out_path):
    # read in the old data
    glob_str = f"{out_path}/{fname_base}*.json"
    files = glob.glob(glob_str)

    # start with our new data
    dataframes = [
        df,
    ]
    # append all the old stuff
    for f in files:
        logger.debug(f"Reading old data from {f}")
        _df = pd.read_json(f)
        dataframes.append(_df)

    # concatenate all the data into a single dataframe
    # ignore a few columns that are just lists, because
    # they can't be hashed when we drop duplicates
    # then sort it all by reference strings (CVE IDs, etc)
    ignore_cols = ["branches", "parents"]
    df = pd.concat(dataframes)
    df = df.drop_duplicates(subset=df.columns.difference(ignore_cols))
    df = df.sort_values(by="reference")
    logger.debug(f"Full data has {len(df)} rows")

    # sort everything by author date
    df["author_date"] = pd.to_datetime(df["author_date"], utc=True)
    df = df.sort_values(by="author_date", ascending=True)

    # figure out the output name and write the json data
    json_fname = f"{fname_base}.json"
    json_file = os.path.join(out_path, json_fname)
    logger.debug(f"Write json data to {json_file}")
    dump_json(df, json_file)

    csv_fname = f"{fname_base}.csv"
    csv_file = os.path.join(out_path, csv_fname)
    logger.debug(f"Write csv data to {csv_file}")
    dump_csv(df, csv_file)

    # clean up the other files
    for f in files:
        # skip the one we just wrote to
        if f == json_file:
            continue
        logger.debug(f"Removing obsolete data file {f}")
        os.remove(f)

    pass


def tag_references(repo, df):
    # sort df by author_date
    df = df.sort_values(by="author_date", ascending=True)
    # drop duplicate refs, keep first
    df = df.drop_duplicates(subset="reference", keep="first")

    def tagger(x):
        # tag the commit with the reference
        (tag_str, commit_ref) = x
        # This happens at the end when we're back to a single process
        # so we shouldn't need to worry about locking
        logger.info(f"Tagging {commit_ref} with {tag_str}")
        repo.create_tag(tag_str, ref=commit_ref, force=True)

    df[["reference", "hash"]].apply(tagger, axis=1)


def init(l):
    """Set up a global lock for multiprocessing"""
    global lock
    lock = l


def main(defaults):
    # parse args
    args = parse_args(defaults)

    # read config
    cfg = read_config(args.cfgpath)

    setup_dirs(cfg)

    logfile = os.path.join(cfg["log_path"], cfg["log_file"])
    setup_file_logger(logfile)

    # clone or refresh repo
    clone_or_pull_repo(cfg["repo_path"], cfg["clone_url"])

    # get list of commits
    logger.info(f"Get list of commit hashes from {cfg['repo_path']}")

    fname_base = cfg["outfile_basename"]

    repo = git.Repo(cfg["repo_path"])
    last_run_tag = "last_run"

    try:
        last_hash_checked = repo.tags[last_run_tag]
    except (AttributeError, IndexError) as e:
        logger.warning(f"Intercepted error: {e}")
        last_hash_checked = None

    most_recent_commit_hash, commit_hashes = get_commit_hashes_from_repo(
        cfg["repo_path"], last_hash_checked
    )

    _commit_handler = partial(
        commit_handler, repo_path=cfg["repo_path"], clone_url=cfg["clone_url"],
    )

    logger.info(f"Processing {len(commit_hashes)} commits...")

    # create a shared lock
    l = mp.Lock()
    pool = mp.Pool(initializer=init, initargs=(l,))
    logger.info(f"Poolsize: {len(pool._pool)}")

    data = []
    if len(commit_hashes):
        commit_data = pool.imap_unordered(func=_commit_handler, iterable=commit_hashes)
        results2 = pool.imap_unordered(func=dh, iterable=commit_data)

        for r in results2:
            data.extend(r)
    else:
        logger.warning("No commit hashes found")

    if len(data):
        logger.info("Create dataframe from commits")
        df = commits_to_df(data)

        # TODO tag the earliest occurrence of each reference in the repo
        tag_references(repo, df)

        if len(df) < 1:
            logger.warning("DataFrame appears empty!")

        logger.info("Writing output data")
        write_data(df, fname_base, cfg["output_path"])

    else:
        logger.warning("No data found")

    logger.info(f"Tagging {most_recent_commit_hash} as {last_run_tag}")
    repo.create_tag(
        last_run_tag, ref=most_recent_commit_hash, message="Last run tag", force=True,
    )

    logger.info("Done")


if __name__ == "__main__":
    main()
