#!/usr/bin/env python
"""
file: demo.py
author: adh
created_at: 3/27/20 8:19 AM
"""
import yaml


def main(cfg_path):
    cfg = _read_config(cfg_path)
    print(cfg)


if __name__ == "__main__":
    main("./config.yaml")
