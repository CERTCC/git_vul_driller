#!/usr/bin/env python
"""
file: patterns
author: adh
created_at: 3/27/20 9:47 AM
"""
import re


IDS = [
    # sometimes with dashes,
    # sometimes with underscores, like in urls
    "CVE[-_][0-9]{4}[-_][0-9]+",
    # find metasploit code mentioning CVE IDs
    "CVE.?,\s+.?[0-9]{4}-[0-9]+",
    # some exploitdb matches CVE : YYYY-nnnnn
    "CVE\s+:\s+[0-9]{4}-[0-9]+",
    "VU\#[0-9]{2,}",
    "BID-\d+",
    # bugtraq id in urls
    "securityfocus\.com/bid/\d+",
    # find metasploit code mentioning BIDs
    "BID.?,\s+.?[0-9]+",
    "OSVDB-\d+",
    # find metasploit code mentioning OSVDBIDs
    "OSVDB.?,\s+.?[0-9]+",
    # find VU# by urls
    "kb\.cert\.org/vuls/id/\d+",
    # ICSA
    "ICSA-[0-9]{2}-[0-9]+-[0-9]+[A-Z]",
    # UVI https://github.com/cloudsecurityalliance/uvi-database
    "UVI-[0-9]{4}-[0-9]+",
    # microsoft
    "MS[0-9]{2}-[0-9]+",
    # zero day inititative (two ID formats)
    "ZDI-CAN-[0-9]+",
    "ZDI-[0-9]{2}-[0-9]+",
    # Google Project Zero
    "bugs\.chromium\.org/p/project-zero/issues/detail\?id=\d+",
    "code.google.com/p/google-security-research/issues/detail\?id=\d+",
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
    #
    # also, since we've already matched the ID patterns above,
    # we can be a bit more liberal in our pattern matching here
    # (e.g., using \D instead of specific delimiters)
    if id_str.startswith("CVE"):
        m = re.match("CVE\D+(\d+)\D+(\d+)", id_str)
        if m:
            return f"CVE-{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("BID"):
        m = re.match("BID\D+(\d+)", id_str)
        if m:
            return f"BID-{m.groups()[0]}"
    elif id_str.startswith("SECURITYFOCUS.COM"):
        m = re.match("SECURITYFOCUS\.COM/BID/(\d+)", id_str)
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
    elif id_str.startswith("UVI"):
        m = re.match("UVI\D+(\d+)\D+(\d+)", id_str)
        if m:
            return f"UVI-{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("MS"):
        m = re.match("MS(\d+)-(\d+)", id_str)
        if m:
            return f"MS{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("ZDI"):
        # Zero Day Initiative has two ID formats
        if id_str.startswith("ZDI-CAN"):
            # ZDI-CAN-NNN
            m = re.match("ZDI-CAN-(\d+)", id_str)
            if m:
                return f"ZDI-CAN-{m.groups()[0]}"
        else:
            # ZDI-NN-NNN
            m = re.match("ZDI-(\d+)-(\d+)", id_str)
            if m:
                return f"ZDI-{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("BUGS.CHROMIUM.ORG"):
        m = re.search("PROJECT-ZERO/ISSUES/DETAIL\?ID=(\d+)", id_str)
        if m:
            return f"GPZ-{m.groups()[0]}"
    elif id_str.startswith("CODE.GOOGLE.COM"):
        m = re.search("GOOGLE-SECURITY-RESEARCH/ISSUES/DETAIL\?id=(\d+)", id_str)
        if m:
            return f"GPZ-{m.groups()[0]}"
        # default to no change
    return id_str
