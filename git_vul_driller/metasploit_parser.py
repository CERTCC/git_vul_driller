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

from git_vul_driller.patterns import PATTERN, normalize
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# _max_logged_records = 20


def find_pattern_matches(str_, pattern, normalizer=None):
    matches = set()

    for m in pattern.findall(str_):
        if normalizer is not None:
            m = normalizer(m)
        matches.add(m)

    return list(matches)


def extract_record(key, record):
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

    # raise NotImplementedError(df.columns)
    # ['description', 'disclosure_date', 'fullname', 'mod_time', 'name',
    #        'path', 'reference', 'source']
    col_order = [
        "reference",
        "disclosure_date",
        "mod_time",
        "path",
        "description",
    ]

    df = df.drop_duplicates()
    df = df[col_order].sort_values(by="mod_time", ascending=True)
    return df
