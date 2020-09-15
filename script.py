#!/usr/bin/env python3


__author__ = "Tinson Lai"
__copyright__ = "Copyright © 2020 Tinson Lai"
__notes__ = """
I assume that Python 3.8 (latest stable version) will be used for this project as there is no version requirement was imposed for this assignment
SyntaxError may raise if using an earlier version due to the following most recent new features:
    Type Hint (weak typing support): based on PEP 484, available from Python 3.5
    f-string (string interpolation): based on PEP 498, available from Python 3.6
    Walrus Operator (assignment expression): based on PEP 572, available from Python 3.8
"""


import json

from git import InvalidGitRepositoryError, NoSuchPathError, Repo
from multiprocessing import Pool
from optparse import OptionParser
from pathlib import Path
from shutil import rmtree
from sys import stderr
from typing import Any, Dict


class _descriptor:
    __slots__ = "_cve_id", "_files", "_fix", "_git", "_repo"

    def __init__(self, repo_dir: Path, values: Dict[str, Any], force=False):
        for k, v in values.items():
            self.__setattr__(f"_{k}", v)

        if (repo_path := repo_dir / self._repo).exists():
            try:
                self._git = Repo(repo_path)
            except InvalidGitRepositoryError as e:
                print(f"failed to read {repo_dir}", file=stderr)
                if force:
                    if repo_path.is_dir():
                        rmtree(repo_path)
                    else:
                        repo_path.unlink()
                else:
                    raise e
                self.git = Repo.clone_from(f"https://github.com/{self._repo}.git", repo_path)
        else:
            self._git = Repo.clone_from(f"https://github.com/{self._repo}.git", repo_path)

    def __str__(self) -> str:
        return f"{{ {self._cve_id} | {self._repo}@{self._fix} }}"

    __repr__ = __str__

    def analyse(self):
        for file in self._files:
            print(self._git.blame(self._fix, file))


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-c", "--config-file", action="store", dest="config_file", type="string", default="./repo.json")
    parser.add_option("-d", "--dest", action="store", dest="dest", type="string", default="./.repo")
    parser.add_option("-f", "--force", action="store_true", dest="force", default=False)

    options, _ = parser.parse_args()

    with open(options.config_file) as f:
        repo_config = json.load(f)

    (repo_dir := Path(options.dest)).mkdir(0o0755, True, True)

    def _new_repo(values: Dict[str, Any]) -> _descriptor:
        return _descriptor(repo_dir, values, options.force)

    with Pool() as pool:
        all_repo = pool.map(_new_repo, repo_config)

        for job in [pool.apply_async(repo.analyse) for repo in all_repo]:
            job.wait()

    # all_repo = (
    #     vulnerability_description(repo_dir, "CVE-2018-1000616", "opennetworkinglab", "onos", "af1fa39a53c0016e92c1de246807879c16f507d6", options.force),
    #     vulnerability_description(repo_dir, "CVE-2017-15719", "sebfz1", "wicket-jquery-ui", "6f33727a1b4aa27d58d672a96154d9061db43fa", options.force)
    # )

    # all_repo[0].analyse()
