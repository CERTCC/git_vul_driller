#!/usr/bin/env python
"""
file: parse_metasploit_metadata
author: adh
created_at: 4/14/21 2:04 PM
"""
import argparse
import logging
import os
import git
from datetime import datetime

import pandas as pd

from git_vul_driller.data_handler import dump_json, read_json
from git_vul_driller.metasploit_parser import mtsp_to_df

logger = logging.getLogger(__name__)


def _parse_args():
    logger.debug("Parsing command line args")
    parser = argparse.ArgumentParser(
        description="Parse vulnerability IDs out of Metasploit Framework's internal metadata"
    )
    parser.add_argument(
        "--mtsp-repo",
        dest="repopath",
        action="store",
        type=str,
        default="data/sources/metasploit-framework",
        help="path to metasploit repo",
    )
    parser.add_argument(
        "--outpath",
        dest="outpath",
        action="store",
        type=str,
        default="data/raw",
        help="path to output directory",
    )
    parser.add_argument(
        "-r",
        "--recent",
        dest="ndays",
        action="store",
        type=int,
        default=-1,
        help="number of days to look back",
    )
    parser.add_argument(
        "--today",
        dest="ndays",
        action="store_const",
        const=1,
        help="shortcut for '--recent 1'",
    )
    parser.add_argument(
        "--thisweek",
        dest="ndays",
        action="store_const",
        const=7,
        help="shortcut for '--recent 7'",
    )
    parser.add_argument(
        "--verbose", dest="loglevel", action="store_const", const=logging.INFO
    )
    parser.add_argument(
        "--debug", dest="loglevel", action="store_const", const=logging.DEBUG
    )

    args = parser.parse_args()

    return args


def pull_repo(repo_path, clone_url):
    repo = git.Repo(repo_path)

    try:
        origin = repo.remotes.origin
    except AttributeError as e:
        origin = repo.create_remote(name="origin", url=clone_url)

    repo.heads.master.set_tracking_branch(origin.refs.master)
    logger.info(f"Pulling master from from {clone_url}")
    origin.pull()


def clone_or_pull_repo(repo_path, clone_url):
    if not os.path.exists(repo_path):
        logger.info(f"No repo found at {repo_path}")
        logger.info(f"Cloning from {clone_url}")

        git.Repo.clone_from(url=clone_url, to_path=repo_path)
    else:
        pull_repo(repo_path, clone_url)


def main():
    logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    args = _parse_args()

    if args.loglevel:
        logger.setLevel(args.loglevel)

    for k, v in vars(args).items():
        logger.debug(f"... {k}: {v}")

    src_dir = "data/sources"
    if not os.path.exists(src_dir):
        logger.info(f"Creating path for cloning {src_dir}")
        os.makedirs(src_dir, exist_ok=True)

    # git pull repo
    # clone or refresh repo
    clone_url = "https://github.com/rapid7/metasploit-framework.git"
    clone_or_pull_repo(args.repopath, clone_url)

    mtsp_json = os.path.join(args.repopath, "db/modules_metadata_base.json")

    if not os.path.exists(mtsp_json):
        print(f"JSON file not found at {mtsp_json}")
        exit(1)

    logger.debug(f"Repo_path: {mtsp_json}")
    data = read_json(mtsp_json)
    df = mtsp_to_df(data)

    if not os.path.exists(args.outpath):
        logger.info(f"Creating path for output {args.outpath}")
        os.makedirs(args.outpath, exist_ok=True)

    outfile = "vul_mentions_metasploit_metadata_base.json"
    outpath = os.path.join(args.outpath, outfile)

    dump_json(df, outpath)

    if args.ndays > 0:
        offset = args.ndays

        today = datetime.now().date()
        start = datetime(today.year, today.month, today.day).astimezone()
        df = df.set_index("mod_time")
        df = df[start - pd.offsets.Day(offset) :]
        df = df.reset_index(drop=False)

    cve_rows = pd.DataFrame(
        df[df["reference"].apply(lambda x: x.lower().startswith("cve-"))]
    )

    pd.set_option("display.width", 20000)
    pd.set_option("display.max_columns", 10000)

    for d in cve_rows.to_dict(orient="records"):
        for k, v in d.items():
            print(f"{k.upper():20}\t{v}")

        print()


if __name__ == "__main__":
    main()
