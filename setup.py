from setuptools import setup

setup(
    name="git_vul_driller",
    version="0.8",
    packages=["git_vul_driller"],
    url="https://vuls.cert.org",
    license="MIT",
    author="adh",
    author_email="adh@cert.org",
    description="Crawl the log history of a git repo and find commits matching a regex",
    scripts=["scripts/update_exploits", "scripts/simple_driller"],
)
