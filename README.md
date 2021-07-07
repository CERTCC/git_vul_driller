# git_repo_crawler
Crawl the logs of a git repo and find commits matching a regex.

## Getting started

1. Edit `config_metasploit.yaml` as needed
2. Edit `config_edb.yaml` as needed
3. Set up your environment (Hint: Use a virtual env)
```bash
$ conda create -n myenv --python=3.8
$ conda activate myenv
$ pip install -r requirements.txt
$ python setup.py install
```
4. Run `update_exploits` Note: This WILL use all your cores until it's done. The first time can take over an hour on a 20-core machine.
   After that it can do incremental updates.
5. Look in `data/raw` for `*.json` and `*.csv` outputs

## Parse Metasploit Metadata

This is a standalone script, and will parse the json metadata file that comes with metasploit.

### Hint: Use a virtual env
```bash
conda create -n myenv --python=3.8
conda activate myenv
pip install pandas

mkdir -P data/raw
mkdir -P data/sources
pushd data/sources
git clone https://github.com/rapid7/metasploit-framework.git
popd
python parse_metasploit_metadata.py
```

Try `python parse_metasploit_metadata.py --help` for a few options:

```
$ python parse_metasploit_metadata.py --help
usage: parse_metasploit_metadata.py [-h] [--mtsp-repo REPOPATH] [--outpath OUTPATH] [-r NDAYS] [--today] [--thisweek] [--verbose] [--debug]

Parse vulnerability IDs out of Metasploit Framework's internal metadata

optional arguments:
  -h, --help            show this help message and exit
  --mtsp-repo REPOPATH  path to metasploit repo
  --outpath OUTPATH     path to output directory
  -r NDAYS, --recent NDAYS
                        number of days to look back
  --today               shortcut for '--recent 1'
  --thisweek            shortcut for '--recent 7'
  --verbose
  --debug

```

Output to screen:
```
REFERENCE               CVE-2012-4915
DISCLOSURE_DATE         2013-01-03 00:00:00
MOD_TIME                2021-04-01 14:17:28+00:00
PATH                    /modules/exploits/unix/webapp/wp_google_document_embedder_exec.rb
DESCRIPTION             This module exploits an arbitrary file disclosure flaw in the WordPress blogging software plugin known as Google Document Embedder. The vulnerability allows for database credential disclosure via the /libs/pdf.php script. The Google Document Embedder plug-in versions 2.4.6 and below are vulnerable. This exploit only works when the MySQL server is exposed on an accessible IP and WordPress has filesystem write access. Please note: The admin password may get changed if the exploit does not run to the end.

REFERENCE               CVE-2019-0307
DISCLOSURE_DATE         NaT
...etc...
```

And in `data/raw/vul_mentions_metasploit_metadata_base.json`:

```
...
{
    "reference":"CVE-2012-5204",
    "disclosure_date":null,
    "mod_time":"2017-07-24T06:26:21Z",
    "path":"\/modules\/auxiliary\/scanner\/http\/hp_imc_ictdownloadservlet_traversal.rb",
    "description":"This module exploits a lack of authentication and a directory traversal in HP Intelligent Management, specifically in the IctDownloadServlet, in order to retrieve arbitrary files with SYSTEM privileges. This module has been tested successfully on HP Intelligent Management Center 5.1 E0202 over Windows 2003 SP2."
},
{
    "reference":"ZDI-13-051",
    "disclosure_date":null,
    "mod_time":"2017-07-24T06:26:21Z",
    "path":"\/modules\/auxiliary\/scanner\/http\/hp_imc_faultdownloadservlet_traversal.rb",
    "description":"This module exploits a lack of authentication and a directory traversal in HP Intelligent Management, specifically in the FaultDownloadServlet, in order to retrieve arbitrary files with SYSTEM privileges. This module has been tested successfully on HP Intelligent Management Center 5.1 E0202 over Windows 2003 SP2."
},
...
```