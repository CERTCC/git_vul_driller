#!/usr/bin/env python
import git
import re
import json
import os
import config as cfg

# invocation:
#  python find_ids_in_git_repos.py ../data/RAW/metasploit/metasploit-framework

# List of Vul ID regexes
IDS = ["CVE-[0-9]{4}-[0-9]+", "CVE.?, +.?[0-9]{4}-[0-9]+", "VU\#[0-9]{2,}"]
# TODO how to match lines like "[ 'CVE', '2007-2386' ]"

ID_REGEX = "|".join(IDS)  # join into one giant regex

PATTERN = re.compile(ID_REGEX, re.I)
ID_REGEX_CLI = f'"{ID_REGEX}"'  # enclose in quotes

# we will cache file creation dates so we don't have to look them up all the time
INIT_DATES = {"author": {}, "committer": {}}


def normalize(id_str):
    # find metasploit code mentioning CVE IDs
    m = re.match("CVE\D+(\d+-\d+)", id_str)
    if m:
        return f"CVE-{m.groups()[0]}"

    # default to no change
    return id_str


def flatten(x):
    return [z for y in x for z in y]


def process_lines(lines):
    for line in lines:
        matches = sorted(list(set([m.upper() for m in PATTERN.findall(line)])))

        if len(matches):
            yield matches


def parse_entry(git_repo, log_entry):
    parsed = {}
    lines = [l.strip() for l in log_entry.split("\n")]

    parts = lines.pop(0).split(",")

    if not len(parts) > 1:
        # bad parse, keep going
        return

    fieldnames = [
        "commit_hash",
        "committer_name",
        "author_date",
        "committer_date",
        "subject",
    ]

    parts_dict = dict((k, v) for k, v in zip(fieldnames, parts))

    parsed.update(parts_dict)

    assert (
        "%aI" not in parsed["author_date"]
    ), "Git is too old to support %aI date format?"
    assert (
        "%cI" not in parsed["committer_date"]
    ), "Git is too old to support %cI date format?"

    # skip blank lines
    lines = [l for l in lines if l.startswith("+")]

    if not len(lines):
        return

    if not lines[0].startswith("+++"):
        print("ERROR!!!")
        exit()

    fpath = lines[0].split(" ")[1]
    # strip leading b/ from fpath...
    fpath = re.sub("^b/", "", fpath)

    parsed["fpath"] = fpath

    # parsed['lines'] = lines

    matches = flatten(list(process_lines(lines)))
    matches = [normalize(m) for m in matches]

    parsed["matches"] = matches

    skip_lookup = ["/dev/null"]

    if fpath in skip_lookup:
        pass
        # print(f'Skipping date lookup on {fpath}')
    else:
        a = INIT_DATES["author"].get(fpath, None)
        c = INIT_DATES["committer"].get(fpath, None)

        # only get them if we haven't already seen them
        if a is None or c is None:
            (a, c) = get_create_date(git_repo, fpath)

        parsed["file_author_init_date"] = a
        parsed["file_committer_init_date"] = c

        INIT_DATES["author"][fpath] = a
        INIT_DATES["committer"][fpath] = c

    return parsed


def get_logs(g):
    loginfo = g.log(
        "--all",
        "--patch",
        "--text",
        '--format=PEALENS|%H,%cn,%aI,%cI,"%s"',  # output formatting
        f"-G{ID_REGEX}",
    )  # regex
    # '--', '.', ':(exclude)db/*')                    #exclude meta_data files - just duplicate information

    return loginfo.split("PEALENS|")


def get_create_date(git_repo, filepath):
    # git log query to return log entry dates (both author and commiter dates) in chronological order
    # (git log defaults to reverse chronological order hence the --reverse flag)
    # this is returns as a \n delimited string
    author_date = None
    commit_date = None

    try:
        dates = git_repo.log(
            "--all", "--pretty=format:'%aI,%cI'", "--reverse", "--", filepath
        )
    except git.exc.GitCommandError as e:
        print(f"Ignoring Error: {e}")
        return (author_date, commit_date)

    # convert to list of strings
    # pick off the first one
    dates = dates.split("\n")[0]

    dates = dates.strip("'").strip()

    # sometimes it's just an empty string
    if not dates:
        return (author_date, commit_date)

    try:
        (author_date, commit_date) = dates.split(",")
        # print(f"dates: {dates}")

    except ValueError as e:
        print(e)

    # return the first array item which should be the first date for the file
    # currently, there are single quotes around this string
    # print(dates[0])
    return (author_date, commit_date)


def main(repo):
    # strip trailing slash, if any
    # then get the basename
    name = os.path.basename(repo.rstrip("/"))

    data = []

    g = git.Git(repo)

    for i, entry in enumerate(get_logs(g)):

        if i % 100 == 0:
            print(f"processed {i} logs so far")

        parsed = parse_entry(g, entry)

        if parsed is None:
            continue

        parsed["origin"] = name

        # parsed has a list of matches.
        # We need to invert that here to get one item per match
        for match in parsed["matches"]:
            item = dict(parsed)
            del item["matches"]
            item["vul_id"] = match
            data.append(item)

    outfile = os.path.join(cfg.COOKED, f"parsed-{name}.json")

    print(f"writing output to {outfile}")

    with open(outfile, "w") as fp:
        json.dump(data, fp, indent=2)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="parse a git repo for vul IDs")
    parser.add_argument(
        "repo_dir", metavar="REPO_DIR", type=str, help="repo dir to search"
    )
    args = parser.parse_args()

    main(args.repo_dir)
