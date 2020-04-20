#!/usr/bin/env python
"""
file: repo_drill
author: adh
created_at: 3/27/20 11:45 AM
"""
import logging
from git_repo_crawler.repo_drill_common import (
    formatter,
    main,
)

defaults = {
    "cfgpath": "../config.yaml",
}

# set up logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level
# add the handlers to the logger
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)


if __name__ == "__main__":
    main(defaults)
