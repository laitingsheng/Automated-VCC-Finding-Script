#!/usr/bin/env python3


__author__ = "Tinson Lai"
__copyright__ = "Copyright © 2020 Tinson Lai"


import math
import re
import yaml

from datetime import timedelta
from git import InvalidGitRepositoryError, Repo
from operator import methodcaller
from optparse import OptionParser
from pathlib import Path
from shutil import rmtree
from sys import stderr
from typing import Any, Dict, List
from unidiff import PatchSet


class _descriptor:
    __slots__ = "cve_id", "files", "fix", "repo", "_git"

    _ignored_patterns = tuple(re.compile(p) for p in (R"^[ \t]*/(?:\*|/).*$", R"^[ \t]*\*/?.*$", R"^[ \t]*$"))

    def __init__(self, repo_dir: Path, values: Dict[str, Any]):
        for k, v in values.items():
            self.__setattr__(k, v)

        if (repo_path := repo_dir / self.repo).exists():
            self._git = Repo(repo_path)
        else:
            self._git = Repo.clone_from(f"https://github.com/{self.repo}.git", repo_path)

    def __str__(self) -> str:
        return f"{self.repo}@{self.fix}({self.cve_id})"

    __repr__ = __str__

    def vcc_heuristic(self) -> List[str]:
        blames = {}
        commit = self._git.commit(self.fix)
        patches = PatchSet(self._git.git.show(commit, "--", *self.files,
                                              format="",
                                              p=True,
                                              color="never"))
        for patch, actual_file in zip(patches, self.files):
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
                    blamed_commit = None
                    for parent_commit in commit.parents:
                        blamed = self._git.blame(parent_commit, actual_file, L=f"{lineno},{lineno}", w=True)
                        if len(blamed) > 1:
                            raise ValueError("blaming a single line yields multiple results")
                        if blamed_commit and blamed_commit != blamed[0][0]:
                            raise ValueError("inconsistent blame across different parents")
                        blamed_commit = blamed[0][0]
                    if not blamed_commit:
                        raise ValueError("invalid empty parent commits list")
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

    def stat(self, commit: str) -> Dict[str, Any]:
        commit = self._git.commit(commit)
        rs = {
            "commit": str(commit),
            "author": commit.author.email,
            "message": commit.message,
            "parents": [str(parent) for parent in commit.parents]
        }

        patches = PatchSet(self._git.git.show(commit, format="", p=True, color="never"))

        added, added_nwc, deleted, deleted_nwc = 0, 0, 0, 0
        affected_files, affected_dirs = set(), set()
        for patch in patches:
            source, target = patch.source_file, patch.target_file
            if source != "/dev/null":
                if source[:2] != "a/":
                    raise ValueError("invalid git diff patch")
                source = Path(source[2:])
                affected_files.add(str(source))
                affected_dirs.add(str(source.parent))
            if target != "/dev/null":
                if target[:2] != "b/":
                    raise ValueError("invalid git diff patch")
                target = Path(target[2:])
                affected_files.add(str(target))
                affected_dirs.add(str(target.parent))
            for hunk in patch:
                for line in hunk:
                    if not any(p.match(line.value) for p in self._ignored_patterns):
                        if line.is_added:
                            added_nwc += 1
                        elif line.is_removed:
                            deleted_nwc += 1
                    if line.is_added:
                        added += 1
                    elif line.is_removed:
                        deleted += 1
        rs["modification"] = {
            "total": {"added": added, "deleted": deleted},
            "no_comment_blank": {"added": added_nwc, "deleted": deleted_nwc}
        }

        total_developers = set()
        total_interval = timedelta(0)
        total_times = 0
        for file in affected_files:
            history = list(self._git.iter_commits(self.fix, file))
            total_interval += history[0].committed_datetime - history[1].committed_datetime
            total_times += len(history)
            total_developers.update(h.author for h in history)
        max_cc, min_cc = 0, float("inf")
        for developer in total_developers:
            cc = len(list(self._git.iter_commits(self.fix, author=developer.email, F=True)))
            if cc > max_cc:
                max_cc = cc
            if cc < min_cc:
                min_cc = cc
        if max_cc == 0 or math.isinf(min_cc):
            raise ValueError("invalid developers list")
        rs["affected"] = {
            "dirs": len(affected_dirs),
            "files": {
                "total": len(affected_files),
                "average_interval": str(total_interval / len(affected_files)),
                "average_times": total_times / len(affected_files),
                "developers": {
                    "total": len(total_developers),
                    "averge": len(total_developers) / len(affected_files),
                    "max_commit": max_cc,
                    "min_commit": min_cc
                }
            }
        }



        return rs


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-c", "--config-file", action="store", dest="config_file", type="string", default="./config.yaml")
    parser.add_option("-d", "--dest", action="store", dest="dest", type="string", default="./.repo")
    parser.add_option("-o", "--output-file", action="store", dest="output_file", type="string", default="./output.yaml")

    options, _ = parser.parse_args()

    with open(options.config_file) as f:
        repo_config = yaml.full_load(f)

    (repo_dir := Path(options.dest)).mkdir(0o0755, True, True)

    with open(options.output_file, 'w') as f:
        yaml.dump([
            {
                "repo": repo.repo,
                "fix_commit": repo.fix,
                "fix_author": (commit := repo._git.commit(repo.fix)).author.email,
                "cve_id": repo.cve_id,
                "vcc": [
                    {
                        "interval": str(commit.committed_datetime - repo._git.commit(vcc).committed_datetime),
                        "stat": repo.stat(vcc)
                    }
                    for vcc in repo.vcc_heuristic()
                ]
            }
            for repo in (_descriptor(repo_dir, values) for values in repo_config)
        ], f)
