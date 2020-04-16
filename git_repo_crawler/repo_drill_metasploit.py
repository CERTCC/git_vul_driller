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
from git_repo_crawler.repo_drill_common import (
    commits_to_df,
    _commit_handler,
    _dh,
    get_commit_hashes_from_repo,
    clone_or_pull_repo,
)


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


if __name__ == "__main__":
    main()
