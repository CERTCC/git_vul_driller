#!/usr/bin/env python
"""
file: demo.py
author: adh
created_at: 3/27/20 8:19 AM
"""
from git_repo_crawler.config import read_config
import logging
import pandas as pd

from git_repo_crawler.data_handler import read_multi_json

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
hdlr = logging.StreamHandler()
logger.addHandler(hdlr)


def clean_data(df):
    # make a copy
    _df = pd.DataFrame(df)

    date_cols = [
        "author_date",
        "committer_date",
    ]

    logger.debug("Converting date rows to timestamps")
    for dc in date_cols:
        _df[dc] = pd.to_datetime(_df[dc])

    logger.debug("Sort records by date")
    _df = _df.sort_values(by="author_date", ascending=True)

    # remove duplicates, keep first (which should be the earliest given the sort we just did)
    logger.debug("Deduplicate records")
    _df = _df.drop_duplicates(subset="reference", keep="first")

    return _df


def cve_only(df):
    is_cve_row = df["reference"].apply(lambda x: x.lower().startswith("cve-"))

    return df[is_cve_row]


def main(cfg_path):
    logger.info(f"Read config from {cfg_path}")
    cfg = read_config(cfg_path)

    logger.info(f"Reading in data...")
    df = read_multi_json(cfg["output_path"])

    logger.info(f"Read {len(df)} rows from CSV files")
    logger.debug("Columns:")
    for c in df.columns:
        logger.debug(f"... {c}")

    df = clean_data(df)
    logger.info(f"Cleaned data has {len(df)} rows")

    cve_df = cve_only(df)
    logger.info(f"Found {len(cve_df)} CVE rows")

    exit()
    # keep only the first time a reference / file path pair appear
    df.sort_values(by="author_date", ascending=True, inplace=True)
    df.drop_duplicates(subset=["reference", "fpath"], keep="first", inplace=True)

    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 10)

    cve_rows = df[df["reference"].apply(lambda x: x.lower().startswith("cve-"))]
    print(cve_rows)


if __name__ == "__main__":
    main("config_metasploit.yaml")
