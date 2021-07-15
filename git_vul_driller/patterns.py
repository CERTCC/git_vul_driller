#!/usr/bin/env python
"""
file: patterns
author: adh
created_at: 3/27/20 9:47 AM
"""
import re


IDS = [
    "CVE-[0-9]{4}-[0-9]+",
    # sometimes with underscores, like in urls
    "CVE_[0-9]{4}_[0-9]+",
    # find metasploit code mentioning CVE IDs
    "CVE.?,\s+.?[0-9]{4}-[0-9]+",
    # some exploitdb matches CVE : YYYY-nnnnn
    "CVE\s+:\s+[0-9]{4}-[0-9]+",
    "VU\#[0-9]{2,}",
    "BID-\d+",
    # find metasploit code mentioning BIDs
    "BID.?,\s+.?[0-9]+",
    "OSVDB-\d+",
    # find metasploit code mentioning OSVDBIDs
    "OSVDB.?,\s+.?[0-9]+",
    # find VU# by urls
    "kb\.cert\.org/vuls/id/\d+",
    # ICSA
    "ICSA-[0-9]{2}-[0-9]+-[0-9]+[A-Z]",
]
ID_REGEX = "|".join(IDS)  # join into one giant regex
PATTERN = re.compile(ID_REGEX, re.I)  # compile it case insensitive

ID_REGEX_CLI = f'"{ID_REGEX}"'  # enclose in quotes


def main():
    pass


if __name__ == "__main__":
    main()


def normalize(id_str):
    id_str = id_str.upper()

    # note: because we're using "startswith" it's ok to use "match"
    # otherwise we'd want to use "search"
    if id_str.startswith("CVE"):
        m = re.match("CVE\D+(\d+)\D+(\d+)", id_str)
        if m:
            return f"CVE-{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("BID"):
        m = re.match("BID\D+(\d+)", id_str)
        if m:
            return f"BID-{m.groups()[0]}"
    elif id_str.startswith("OSVDB"):
        m = re.match("OSVDB\D+(\d+)", id_str)
        if m:
            return f"OSVDB-{m.groups()[0]}"
    elif id_str.startswith("VU"):
        m = re.match("VU\D+(\d+)", id_str)
        if m:
            return f"VU#{m.groups()[0]}"
    elif id_str.startswith("KB.CERT.ORG"):
        m = re.match("KB\.CERT\.ORG/VULS/ID/(\d+)", id_str)
        if m:
            return f"VU#{m.groups()[0]}"
    elif id_str.startswith("ICSA"):
        m = re.match("ICSA-(\d+)-(\d+)-(\d+\w?)", id_str)
        if m:
            return f"ICSA-{m.groups()[0]}-{m.groups()[1]}-{m.groups()[2]}"
    # default to no change
    return id_str
