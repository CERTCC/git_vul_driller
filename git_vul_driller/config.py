#!/usr/bin/env python
"""
file: config
author: adh
created_at: 4/9/20 10:08 AM
"""
import os
import yaml
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def main():
    pass


if __name__ == "__main__":
    main()


def read_config(cfg_path):
    logger.debug(f"Reading config from {cfg_path}")
    with open(cfg_path, "r") as fp:
        cfg = yaml.safe_load(fp)

    if not os.path.isdir(cfg["work_path"]) and os.path.isdir(
        os.path.join("..", cfg["work_path"])
    ):
        cfg["work_path"] = os.path.join("..", cfg["work_path"])
    if not os.path.isdir(cfg["output_path"]) and os.path.isdir(
        os.path.join("..", cfg["output_path"])
    ):
        cfg["output_path"] = os.path.join("..", cfg["output_path"])

    cfg["work_path"] = os.path.abspath(os.path.expanduser(cfg["work_path"]))
    cfg["repo_path"] = os.path.join(cfg["work_path"], cfg["repo_path"])
    cfg["output_path"] = os.path.abspath(os.path.expanduser(cfg["output_path"]))

    for k, v in cfg.items():
        logger.debug(f"... {k} = {v}")

    return cfg
