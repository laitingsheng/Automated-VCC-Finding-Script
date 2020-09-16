#!/usr/bin/env python3


__author__ = "Tinson Lai"
__copyright__ = "Copyright © 2020 Tinson Lai"


import re
import json

from git import InvalidGitRepositoryError, NoSuchPathError, Repo
from multiprocessing import Pool
from operator import methodcaller
from optparse import OptionParser
from pathlib import Path
from shutil import rmtree
from sys import stderr
from typing import Any, Dict
from unidiff import PatchSet


class _descriptor:
    __slots__ = "_cve_id", "_files", "_fix", "_git", "_repo"

    _ignored_patterns = re.compile(R"^[ \t]*/(?:\*|/).*$"), re.compile(R"^[ \t]*\*/?.*$")

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

    def vcc_heuristic(self):
        blames = {}
        for parent_commit in (commit := self._git.commit(self._fix)).parents:
            patches = PatchSet(self._git.git.diff(parent_commit, commit, *self._files, color="never"))
            for patch, actual_file in zip(patches, self._files):
                if f"a/{actual_file}" != patch.source_file or f"b/{actual_file}" != patch.target_file:
                    raise ValueError("inconsistent file names in patch")
                for hunk in patch:
                    prev_line = None
                    blamed_linenos = set()
                    for line in hunk:
                        if not any(p.match(line.value) for p in self._ignored_patterns):
                            if line.is_removed:
                                blamed_linenos.add(line.source_line_no)
                            elif line.is_added:
                                if prev_line and prev_line.is_context:
                                    blamed_linenos.add(prev_line.source_line_no)
                            elif line.is_context:
                                if prev_line and prev_line.is_added:
                                    blamed_linenos.add(line.source_line_no)
                        prev_line = line
                    for lineno in blamed_linenos:
                        blamed = self._git.blame(parent_commit, actual_file, L=f"{lineno},{lineno}")
                        if len(blamed) > 1:
                            raise ValueError("blaming a single line yields multiple results")
                        blamed_commit, _ = blamed[0]
                        blamed_commit_str = str(blamed_commit)
                        blames[blamed_commit_str] = blames.get(blamed_commit_str, 0) + 1

        mv = 0
        record = []
        for k, v in blames.items():
            if v > mv:
                record = [k]
                mv = v
            elif v == mv:
                record.append(k)
        return record


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

        for repo, vcc in zip(all_repo, pool.map(methodcaller('vcc_heuristic'), all_repo)):
            print(f"{repo}: {vcc}")

    # all_repo = (
    #     vulnerability_description(repo_dir, "CVE-2018-1000616", "opennetworkinglab", "onos", "af1fa39a53c0016e92c1de246807879c16f507d6", options.force),
    #     vulnerability_description(repo_dir, "CVE-2017-15719", "sebfz1", "wicket-jquery-ui", "6f33727a1b4aa27d58d672a96154d9061db43fa", options.force)
    # )

    # all_repo[0].analyse()
