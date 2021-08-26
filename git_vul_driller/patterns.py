#!/usr/bin/env python
"""
file: patterns
author: adh
created_at: 3/27/20 9:47 AM
"""
import re
import os
from labyrinth.errors import LabyrinthPatternError

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
    # Zero Science Lab
    "ZSL-[0-9]{4}-[0-9]+",
    # china nvd
    "CNVD[-_]\d[0-9]{4}[-_][0-9]+",
    # china nvd
    "CNVD[-_]C[-_][0-9]{4}[-_][0-9]+",
    # china NNVD CNNVD-{YYYY}{MM}-{NNN}
    "CNNVD[-_][0-9]{6}[-_][0-9]+",
]
ID_REGEX = "|".join(IDS)  # join into one giant regex
PATTERN = re.compile(ID_REGEX, re.I)  # compile it case insensitive

ID_REGEX_CLI = f'"{ID_REGEX}"'  # enclose in quotes


def find_vul_ids(str):
    matches = (normalize(m) for m in PATTERN.findall(str))
    matches = sorted(list(set(matches)))
    return matches


def normalize(id_str):
    id_str = id_str.upper()

    # note: because we're using "startswith" it's ok to use "match"
    # otherwise we'd want to use "search"
    #
    # also, since we've already matched the ID patterns above,
    # we can be a bit more liberal in our pattern matching here
    # (e.g., using \D instead of specific delimiters)
    if id_str.startswith("CVE"):
        m = re.match("CVE\D+(\d+)\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"CVE-{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("BID"):
        m = re.match("BID\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"BID-{m.groups()[0]}"
    elif id_str.startswith("SECURITYFOCUS.COM"):
        m = re.match("SECURITYFOCUS\.COM/BID/(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"BID-{m.groups()[0]}"
    elif id_str.startswith("OSVDB"):
        m = re.match("OSVDB\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"OSVDB-{m.groups()[0]}"
    elif id_str.startswith("VU"):
        m = re.match("VU\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"VU#{m.groups()[0]}"
    elif id_str.startswith("KB.CERT.ORG"):
        m = re.match("KB\.CERT\.ORG/VULS/ID/(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"VU#{m.groups()[0]}"
    elif id_str.startswith("ICSA"):
        m = re.match("ICSA\D+(\d+)\D+(\d+)\D+(\d+\w?)", id_str, re.IGNORECASE)
        if m:
            return f"ICSA-{m.groups()[0]}-{m.groups()[1]}-{m.groups()[2]}"
    elif id_str.startswith("UVI"):
        m = re.match("UVI\D+(\d+)\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"UVI-{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("MS"):
        m = re.match("MS(\d+)\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"MS{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("ZDI"):
        # Zero Day Initiative has two ID formats
        if id_str.startswith("ZDI-CAN"):
            # ZDI-CAN-NNN
            m = re.match("ZDI[^C]+CAN\D+(\d+)", id_str, re.IGNORECASE)
            if m:
                return f"ZDI-CAN-{m.groups()[0]}"
        else:
            # ZDI-NN-NNN
            m = re.match("ZDI\D+(\d+)\D+(\d+)", id_str, re.IGNORECASE)
            if m:
                return f"ZDI-{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("ZSL"):
        # ZDI-NN-NNN
        m = re.match("ZSL\D+(\d+)\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"ZSL-{m.groups()[0]}-{m.groups()[1]}"
    elif id_str.startswith("BUGS.CHROMIUM.ORG"):
        m = re.search("PROJECT-ZERO/ISSUES/DETAIL\?ID=(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"GPZ-{m.groups()[0]}"
    elif id_str.startswith("CODE.GOOGLE.COM"):
        m = re.search(
            "GOOGLE-SECURITY-RESEARCH/ISSUES/DETAIL\?ID=(\d+)", id_str, re.IGNORECASE
        )
        if m:
            return f"GPZ-{m.groups()[0]}"
    elif id_str.startswith("CNVD"):
        m = re.search("CNVD\D+(\d+)\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"CNVD-{m.groups()[0]}-{m.groups()[1]}"
        # candidates?
        m = re.search("CNVD[^C]+C\D+(\d+)\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"CNVD-C-{m.groups()[0]}-{m.groups()[1]}"

    elif id_str.startswith("CNNVD"):
        m = re.search("CNNVD\D+(\d+)\D+(\d+)", id_str, re.IGNORECASE)
        if m:
            return f"CNNVD-{m.groups()[0]}-{m.groups()[1]}"

    # default to no change
    return id_str


def id_to_path(id_str):
    parts = None

    if id_str.startswith("VU#"):
        m = re.match("(VU)#(\d{2})", id_str)
        if m:
            parts = [m.groups()[0], m.groups()[1], id_str]
    elif id_str.count("-") > 1:
        parts = id_str.split("-")

        # special handling for CNVD-C-YYYY etc
        if parts[0] == "CNVD" and "C" in parts:
            # remove the "C" from parts
            parts.remove("C")

        parts = parts[:-1]
        parts.append(id_str)
    elif id_str.count("-") == 1:
        # MS08-067 like
        m = re.match("([a-z]+)(\d+)-(\d+)", id_str, re.IGNORECASE)
        if m:
            parts = [m.groups()[0], m.groups()[1], id_str]
        else:
            # BID-10108 like - we just want the first 2 digits to spread the files out
            m = re.match("([a-z]+)-(\d{1,2})", id_str, re.IGNORECASE)
            if m:
                parts = [m.groups()[0], m.groups()[1], id_str]

    if parts is None:
        raise LabyrinthPatternError(
            f"Could not parse id string {id_str} into directories"
        )

    return os.path.join(*parts)


def repo_id_to_path(id_str):
    # make sure it's a string not an int
    id_str = str(id_str)
    # split it into chunks
    parts = re.findall(".{1,2}", id_str)
    # take up to the first 3 chunks
    # (list slices are tolerant when there are less than 3)
    parts = parts[:3]
    parts.append(id_str)

    return os.path.join(*parts)
