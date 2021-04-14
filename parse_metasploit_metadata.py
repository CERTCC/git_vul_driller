#!/usr/bin/env python
'''
file: parse_metasploit_metadata
author: adh
created_at: 4/14/21 2:04 PM
'''
import argparse
import logging
import os

import pandas as pd

from git_repo_crawler.data_handler import dump_json, read_json
from git_repo_crawler.metasploit_parser import mtsp_to_df

logger = logging.getLogger(__name__)
hdlr = logging.StreamHandler()


def _parse_args():
    logger.debug("Parsing command line args")
    parser = argparse.ArgumentParser(
        description="Parse vulnerability IDs out of Metasploit Framework's internal metadata"
    )
    parser.add_argument(
        "--config",
        dest="cfgpath",
        action="store",
        type=str,
        default="./config_metasploit.yaml",
        help="path to config_metasploit.yaml",
    )
    parser.add_argument(
            "--mtsp-repo",
            dest="repopath",
            action="store",
            type=str,
            default="data/sources/metasploit-framework",
            help="path to metasploit repo"
    )

    parser.add_argument(
            "--outpath",
            dest="outpath",
            action="store",
            type=str,
            default="data/raw",
            help="path to output directory"
    )

    args = parser.parse_args()

    for k, v in vars(args).items():
        logger.debug(f"... {k}: {v}")
    return args


def main():
    args = _parse_args()
    mtsp_json = os.path.join(args.repopath, "db/modules_metadata_base.json")

    logger.debug(f"Repo_path: {mtsp_json}")
    data = read_json(mtsp_json)
    df = mtsp_to_df(data)


    outfile = "vul_mentions_metasploit_metadata_base.json"
    outpath = os.path.join(args.outpath, outfile)

    dump_json(df, outpath)


    cve_rows = pd.DataFrame(df[df['reference'].apply(lambda x: x.lower().startswith("cve-"))])

    pd.set_option("display.width", 20000)
    pd.set_option("display.max_columns", 10000)

    for d in cve_rows.to_dict(orient="records"):
        for k,v in d.items():
            print(f"{k.upper():20}\t{v}")

        print()

if __name__ == '__main__':
    main()
