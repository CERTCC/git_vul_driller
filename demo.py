#!/usr/bin/env python
"""
file: demo.py
author: adh
created_at: 3/27/20 8:19 AM
"""
import yaml
import os
from glob import glob
from git_repo_crawler.config import _read_config
import logging
import pandas as pd

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
hdlr = logging.StreamHandler()
logger.addHandler(hdlr)


def read_json(output_path):
    logger.debug(f"Looking for json files in {output_path}")
    jsonfiles = glob(os.path.join(output_path, "vul_sightings_*.json"))

    dataframes = []
    for f in jsonfiles:
        logger.debug(f"Found file {f}")
        _df = pd.read_json(f, orient="table")

        dataframes.append(_df)

    df = pd.concat(dataframes)
    return df


def clean_data(df):
    # make a copy
    _df = pd.DataFrame(df)

    date_cols = [
        "author_date",
        "committer_date",
    ]
    for dc in date_cols:
        _df[dc] = pd.to_datetime(_df[dc])

    # sort by date
    _df = _df.sort_values(by="author_date", ascending=True)

    # remove duplicates, keep first (which should be the earliest given the sort we just did)
    _df = _df.drop_duplicates(subset="reference", keep="first")

    return _df


def cve_only(df):
    is_cve_row = df["reference"].apply(lambda x: x.lower().startswith("cve-"))

    return df[is_cve_row]


def main(cfg_path):
    logger.info(f"Read config from {cfg_path}")
    cfg = _read_config(cfg_path)

    logger.info(f"Reading in data...")
    df = read_json(cfg["output_path"])

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
    main("./config.yaml")
