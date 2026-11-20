"""Minimal GitHub event capture for the sandbox trial (stdlib only; reads files and the environment, writes JSON).

Purpose: record the REAL shape of GitHub events with the least data possible, so that local adapters can be compared
against reality on a developer machine. Nothing here talks to the network, runs PR code or prints a token.

  context       selected values of the Actions context passed as environment variables (never read from `env` wholesale)
  event         reduce an event payload (workflow_dispatch / pull_request / workflow_run) + write its key-path SHAPE
  rest-pr       reduce a REST "Get a pull request" response + write its SHAPE
  changed       REST "List pull request files" response -> `git diff --name-status` style lines
  pr-number     print the single pull request number named by a workflow_run payload (empty if none / ambiguous)
  inventory     list regular files of a directory (name, size, sha256) WITHOUT parsing them (untrusted artifact)

Every output is scanned for token-like strings and refused if one is found. The SHAPE of a payload is the sorted list of
`path:type` strings (array indexes written as `[]`): no values, so it carries no personal data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

TOKENISH = re.compile(r"(gh[pousr]_[A-Za-z0-9]{20,}|github_" r"pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_\-]{16,}|"
                      r"Bearer\s+[A-Za-z0-9._\-]{16,}|-----BEGIN [A-Z ]*PRIV" r"ATE KEY-----|"
                      r"AKIA[0-9A-Z]{16})")
CONTEXT_ENV = {          # output key -> environment variable the workflow sets from `${{ github.* }}` (allowlist)
    "event_name": "EVENT_NAME", "repository": "REPOSITORY", "repository_id": "REPOSITORY_ID",
    "repository_owner": "REPOSITORY_OWNER", "run_id": "RUN_ID", "run_attempt": "RUN_ATTEMPT",
    "run_number": "RUN_NUMBER", "workflow": "WORKFLOW", "job": "JOB", "sha": "SHA", "ref": "REF",
    "ref_name": "REF_NAME", "ref_protected": "REF_PROTECTED", "actor": "ACTOR", "triggering_actor": "TRIGGERING_ACTOR",
    "event_action": "EVENT_ACTION", "default_branch": "DEFAULT_BRANCH",
    "runner_os": "RUNNER_OS", "runner_arch": "RUNNER_ARCH", "runner_environment": "RUNNER_ENVIRONMENT",
}
MAX_IN = 8 * 1024 * 1024


class CaptureError(Exception):
    pass


def _load(path: str):
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_IN:
        raise CaptureError(f"{p.name}: not a regular file or too large")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        raise CaptureError(f"{p.name}: not valid JSON") from None


def _load_many(path: str) -> list:
    """`gh api --paginate --jq '.[]'` prints one JSON value per element (JSON lines); a plain JSON array also works."""
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_IN:
        raise CaptureError(f"{p.name}: not a regular file or too large")
    text, dec, i, out = p.read_text(encoding="utf-8"), json.JSONDecoder(), 0, []
    try:
        while True:
            while i < len(text) and text[i].isspace():
                i += 1
            if i >= len(text):
                return out
            v, i = dec.raw_decode(text, i)
            out.extend(v) if isinstance(v, list) else out.append(v)
    except ValueError:
        raise CaptureError(f"{p.name}: not valid JSON") from None


def _g(obj, *path):
    """Value at the path or None (never raises): missing data must show up as null, not as a crash."""
    for k in path:
        if not isinstance(obj, dict) or k not in obj:
            return None
        obj = obj[k]
    return obj


def shape(obj) -> list[str]:
    """Sorted unique `path:type` list of every node (containers included), array indexes as `[]`. No values."""
    out: set[str] = set()

    def walk(o, prefix):
        t = "null" if o is None else "boolean" if isinstance(o, bool) else "number" if isinstance(o, (int, float)) \
            else "string" if isinstance(o, str) else "array" if isinstance(o, list) else "object"
        if prefix:
            out.add(f"{prefix}:{t}")
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(o, list):
            for v in o:
                walk(v, f"{prefix}.[]" if prefix else "[]")

    walk(obj, "")
    return sorted(out)


def _repo(r):
    return None if not isinstance(r, dict) else {"full_name": r.get("full_name"), "fork": r.get("fork")}


def _labels(lst):
    return [{"name": _g(x, "name")} for x in lst] if isinstance(lst, list) else None


def _pr_core(pr):
    head, base = _g(pr, "head"), _g(pr, "base")
    return {"number": _g(pr, "number"), "state": _g(pr, "state"), "draft": _g(pr, "draft"),
            "merged": _g(pr, "merged"), "updated_at": _g(pr, "updated_at"), "labels": _labels(_g(pr, "labels")),
            "base": {"ref": _g(base, "ref"), "sha": _g(base, "sha"), "repo": _repo(_g(base, "repo"))},
            "head": {"ref": _g(head, "ref"), "sha": _g(head, "sha"), "repo": _repo(_g(head, "repo"))}}


def reduce_dispatch(ev):
    return {"ref": _g(ev, "ref"), "workflow": _g(ev, "workflow"), "inputs": _g(ev, "inputs"),
            "repository": {"full_name": _g(ev, "repository", "full_name"),
                           "default_branch": _g(ev, "repository", "default_branch"),
                           "private": _g(ev, "repository", "private")},
            "sender": {"login": _g(ev, "sender", "login"), "type": _g(ev, "sender", "type")}}


def reduce_pull_request(ev):
    return {"action": _g(ev, "action"), "number": _g(ev, "number"),
            "repository": {"full_name": _g(ev, "repository", "full_name"),
                           "default_branch": _g(ev, "repository", "default_branch"),
                           "private": _g(ev, "repository", "private")},
            "sender": {"login": _g(ev, "sender", "login"), "type": _g(ev, "sender", "type")},
            "pull_request": _pr_core(_g(ev, "pull_request"))}


def reduce_workflow_run(ev):
    wr = _g(ev, "workflow_run")
    prs = _g(wr, "pull_requests")
    return {"action": _g(ev, "action"),
            "repository": {"full_name": _g(ev, "repository", "full_name")},
            "sender": {"login": _g(ev, "sender", "login"), "type": _g(ev, "sender", "type")},
            "workflow_run": {
                "id": _g(wr, "id"), "run_attempt": _g(wr, "run_attempt"), "run_number": _g(wr, "run_number"),
                "name": _g(wr, "name"), "path": _g(wr, "path"), "workflow_id": _g(wr, "workflow_id"),
                "event": _g(wr, "event"), "status": _g(wr, "status"), "conclusion": _g(wr, "conclusion"),
                "head_sha": _g(wr, "head_sha"), "head_branch": _g(wr, "head_branch"),
                "created_at": _g(wr, "created_at"), "updated_at": _g(wr, "updated_at"),
                "repository": {"full_name": _g(wr, "repository", "full_name")},
                "head_repository": _repo(_g(wr, "head_repository")),
                "actor": {"login": _g(wr, "actor", "login")},
                "triggering_actor": {"login": _g(wr, "triggering_actor", "login")},
                "pull_requests": ([{"number": _g(x, "number"), "head": {"ref": _g(x, "head", "ref"),
                                                                       "sha": _g(x, "head", "sha")},
                                    "base": {"ref": _g(x, "base", "ref"), "sha": _g(x, "base", "sha")}}
                                   for x in prs] if isinstance(prs, list) else None)}}


def reduce_rest_pr(pr):
    out = _pr_core(pr)
    out["mergeable_state_present"] = isinstance(pr, dict) and "mergeable_state" in pr
    out["user"] = {"login": _g(pr, "user", "login")}
    return out


REDUCERS = {"dispatch": reduce_dispatch, "pull_request": reduce_pull_request, "workflow_run": reduce_workflow_run}
_STATUS = {"added": "A", "modified": "M", "removed": "D", "renamed": "R100", "copied": "C100", "changed": "M"}


def changed_name_status(files) -> str:
    if not isinstance(files, list) or len(files) > 3000:
        raise CaptureError("files: list of at most 3000 entries")
    lines = []
    for f in files:
        name, st = _g(f, "filename"), _STATUS.get(_g(f, "status"))
        if st is None or not isinstance(name, str) or not name or "\t" in name or "\n" in name:
            raise CaptureError("files: unusable entry (unknown status or filename)")
        prev = _g(f, "previous_filename")
        if st[0] in "RC":
            if not isinstance(prev, str) or not prev or "\t" in prev or "\n" in prev:
                raise CaptureError("files: rename/copy without a usable previous_filename")
            lines.append(f"{st}\t{prev}\t{name}")
        else:
            lines.append(f"{st}\t{name}")
    return "\n".join(lines) + ("\n" if lines else "")


def pr_number(ev) -> str:
    prs = _g(ev, "workflow_run", "pull_requests")
    nums = sorted({_g(x, "number") for x in prs if isinstance(_g(x, "number"), int)}) if isinstance(prs, list) else []
    return str(nums[0]) if len(nums) == 1 and not isinstance(nums[0], bool) and nums[0] > 0 else ""


def inventory(directory: str) -> dict:
    d = Path(directory)
    files = []
    for p in sorted(d.rglob("*")):
        if p.is_symlink() or not p.exists():
            files.append({"name": p.relative_to(d).as_posix(), "kind": "symlink-or-broken", "size": None,
                          "sha256": None})
        elif p.is_file():
            size = p.stat().st_size
            files.append({"name": p.relative_to(d).as_posix(), "kind": "file", "size": size,
                          "sha256": hashlib.sha256(p.read_bytes()).hexdigest() if size <= MAX_IN * 4 else None})
    return {"files": files, "parsed": False, "executed": False}


def context_from_env(env) -> dict:
    return {k: (env.get(v) if env.get(v) not in (None, "") else None) for k, v in CONTEXT_ENV.items()}


def _write(path: Path, doc) -> None:
    text = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    if TOKENISH.search(text):
        raise CaptureError(f"{path.name}: token-like string found; refusing to write")
    path.write_text(text, encoding="utf-8")


def main(argv=None, env=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    try:
        if not argv:
            raise CaptureError("usage: capture.py context|event|rest-pr|changed|pr-number|inventory ...")
        cmd, a = argv[0], argv[1:]

        def opt(name):
            if name not in a or a.index(name) + 1 >= len(a):
                raise CaptureError(f"missing {name}")
            return a[a.index(name) + 1]
        if cmd == "context":
            out = Path(opt("--out-dir"))
            out.mkdir(parents=True, exist_ok=True)
            _write(out / "context.json", context_from_env(env))
        elif cmd == "event":
            kind, ev, out = opt("--kind"), _load(opt("--event-file")), Path(opt("--out-dir"))
            if kind not in REDUCERS:
                raise CaptureError("--kind: dispatch | pull_request | workflow_run")
            out.mkdir(parents=True, exist_ok=True)
            _write(out / f"{kind}.reduced.json", REDUCERS[kind](ev))
            _write(out / f"{kind}.shape.json", shape(ev))
        elif cmd == "rest-pr":
            pr, out = _load(opt("--in")), Path(opt("--out-dir"))
            out.mkdir(parents=True, exist_ok=True)
            _write(out / "rest-pr.reduced.json", reduce_rest_pr(pr))
            _write(out / "rest-pr.shape.json", shape(pr))
        elif cmd == "changed":
            out = Path(opt("--out-dir"))
            out.mkdir(parents=True, exist_ok=True)
            text = changed_name_status(_load_many(opt("--in")))
            if TOKENISH.search(text):
                raise CaptureError("changed.txt: token-like string found; refusing to write")
            (out / "changed.txt").write_text(text, encoding="utf-8")
        elif cmd == "pr-number":
            print(pr_number(_load(opt("--event-file"))))
        elif cmd == "inventory":
            out = Path(opt("--out-dir"))
            out.mkdir(parents=True, exist_ok=True)
            _write(out / "artifact-inventory.json", inventory(opt("--dir")))
        else:
            raise CaptureError("unknown command")
    except CaptureError as e:
        print(f"capture: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
