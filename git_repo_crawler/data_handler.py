#!/usr/bin/env python
"""
file: data_handler
author: adh
created_at: 4/13/20 11:30 AM
"""
import os
from glob import glob
import pandas as pd
import logging
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def read_json(jsonfile):
    with open(jsonfile, "r") as fp:
        data = json.load(fp)
    return data


def read_multi_json(output_path):
    logger.debug(f"Looking for json files in {output_path}")
    jsonfiles = glob(os.path.join(output_path, "vul_sightings_*.json"))

    dataframes = []
    for f in jsonfiles:
        logger.debug(f"Found file {f}")

        data = pd.read_json(f)

        _df = pd.DataFrame(data)

        dataframes.append(_df)

    df = pd.concat(dataframes)
    return df


def dump_json(df, json_file):

    logger.info(f"Write to {json_file}")
    df.to_json(
        path_or_buf=json_file,
        orient="records",
        date_format="iso",
        date_unit="s",
        indent=2,
    )


def dump_csv(c_hash, df, output_path):
    fname_base = f"vul_sightings_{c_hash}"
    csv_fname = f"{fname_base}.csv"
    csv_file = os.path.join(output_path, csv_fname)
    logger.info(f"Write to {csv_file}")
    df.to_csv(path_or_buf=csv_file, index=False)


def main():
    pass


if __name__ == "__main__":
    main()
