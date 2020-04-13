#!/usr/bin/env python
"""
file: metasploit_parser
author: adh
created_at: 3/27/20 9:55 AM

Metasploit contains a file called "modules_metadata_base.json"

This module parses that json file and extracts some useful fields into a pandas dataframe
"""
import json
from pprint import pformat
import pandas as pd

import logging

logging.basicConfig(
    filename="../log/metasploit_parser.log", filemode="w", level=logging.DEBUG
)

logger = logging.getLogger(__name__)


_logged_record_count = 0
_max_logged_records = 20
_done_logging = False


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
    refs = record.get("references")
    fields = [k for k in record.keys() if k != "references"]

    inverted = []
    for ref in refs:
        new_rec = {k: record[k] for k in fields}
        new_rec["reference"] = ref
        inverted.append(new_rec)
    return inverted


def main():
    mtsp_json = "../data/metasploit-framework/db/modules_metadata_base.json"
    data = read_mstp_json(mtsp_json)
    df = mtsp_to_df(data)

    df.to_json(
        path_or_buf="../output/vul_mentions_metasploit_metadata_base.json",
        orient="table",
        date_format="iso",
        date_unit="s",
        indent=2,
    )

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


def mtsp_to_df(data):
    rows = []
    max = 100000
    for k, v in data.items():
        rec = extract_record(k, v)
        new_rows = invert_refs(rec)
        rows.extend(new_rows)

        # break early
        if not max:
            break
        max -= 1
    df = pd.DataFrame(rows)

    # eliminate extra whitespace
    df["description"] = df["description"].apply(lambda x: " ".join(x.split()))
    df["mod_time"] = pd.to_datetime(df["mod_time"])
    df["disclosure_date"] = pd.to_datetime(df["disclosure_date"])
    df["source"] = "metasploit_framework_db"
    return df


def read_mstp_json(mtsp_json):
    with open(mtsp_json, "r") as fp:
        data = json.load(fp)
    return data


if __name__ == "__main__":
    main()
