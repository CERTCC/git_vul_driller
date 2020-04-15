#!/usr/bin/env python
"""
file: metasploit_parser
author: adh
created_at: 3/27/20 9:55 AM

Metasploit contains a file called "modules_metadata_base.json"

This module parses that json file and extracts some useful fields into a pandas dataframe
"""
from pprint import pformat
import pandas as pd
import argparse
from git_repo_crawler.config import read_config
import os
from git_repo_crawler.patterns import PATTERN, normalize
import logging

from git_repo_crawler.data_handler import read_json, dump_json


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
hdlr = logging.StreamHandler()
hdlr.setLevel(logging.DEBUG)
logger.addHandler(hdlr)

_logged_record_count = 0
_max_logged_records = 20
_done_logging = False


def find_pattern_matches(str_, pattern, normalizer=None):
    matches = set()

    for m in pattern.findall(str_):
        if normalizer is not None:
            m = normalizer(m)
        matches.add(m)

    return list(matches)


def extract_record(key, record):
    global _logged_record_count
    global _done_logging

    fields = [
        "description",
        "disclosure_date",
        "fullname",
        "mod_time",
        "name",
        "path",
        "references",
    ]

    extracted = {k: record[k] for k in fields}

    if _logged_record_count < _max_logged_records:
        logger.debug(key)
        logger.debug(pformat(record))
        logger.debug(pformat(extracted))
        _logged_record_count += 1
    elif not _done_logging:
        logger.debug(
            f"Stopped logging records after count reached {_max_logged_records}"
        )
        _done_logging = True

    return extracted


def invert_refs(record):
    fields = [k for k in record.keys() if k != "references"]

    refs = []
    for ref in record.get("references"):
        refs.append(ref)

        matches = find_pattern_matches(ref, pattern=PATTERN, normalizer=normalize)
        refs.extend(matches)

    inverted = []
    for ref in refs:
        new_rec = {k: record[k] for k in fields}
        new_rec["reference"] = ref
        inverted.append(new_rec)
    return inverted


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
        default="../config.yaml",
        help="path to config.yaml",
    )

    args = parser.parse_args()

    for k, v in vars(args).items():
        logger.debug(f"... {k}: {v}")
    return args


def mtsp_to_df(data):
    """In: the metasploit metadata json as a python object
    Out: a pandas dataframe"""
    rows = []
    for k, v in data.items():
        rec = extract_record(k, v)
        new_rows = invert_refs(rec)
        rows.extend(new_rows)

    df = pd.DataFrame(rows)

    # eliminate extra whitespace
    df["description"] = df["description"].apply(lambda x: " ".join(x.split()))
    df["mod_time"] = pd.to_datetime(df["mod_time"])
    df["disclosure_date"] = pd.to_datetime(df["disclosure_date"])
    df["source"] = "metasploit_framework_db"

    df = df.drop_duplicates()
    return df


def main():

    args = _parse_args()

    cfg = read_config(args.cfgpath)

    mtsp_json = os.path.join(cfg["repo_path"], "db/modules_metadata_base.json")

    logger.debug(f"Repo_path: {mtsp_json}")

    data = read_json(mtsp_json)
    df = mtsp_to_df(data)

    outfile = "vul_mentions_metasploit_metadata_base.json"
    outpath = os.path.join(cfg["output_path"], outfile)

    dump_json(df, outpath)

    logger.debug(df.__str__())

    cve_rows = df[df["reference"].apply(lambda x: x.lower().startswith("cve-"))]
    osvdb_rows = df[df["reference"].apply(lambda x: x.lower().startswith("osvdb-"))]
    bid_rows = df[df["reference"].apply(lambda x: x.lower().startswith("bid-"))]

    print(cve_rows["reference"].nunique())
    print(osvdb_rows["reference"].nunique())
    print(bid_rows["reference"].nunique())

    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 10)
    print(cve_rows[["name", "mod_time", "disclosure_date", "reference"]])

    print(
        cve_rows[cve_rows["mod_time"] > "2020/02/01"][
            ["name", "mod_time", "disclosure_date", "reference"]
        ]
    )


if __name__ == "__main__":
    main()
