#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

"""Check the public T1/T2 biometric research watchlist once per local day.

The state file lives outside the repository so an ordinary daily observation
does not dirty a hardware checkpoint.  This tool detects changes and linked
GitHub repositories; it never treats an upstream claim as protocol authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPOSITORY_ROOT / "docs" / "external-research-sources.json"
DEFAULT_STATE = (
    Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    / "t2-touchid-linux"
    / "external-research-watch.json"
)
GITHUB_REPOSITORY = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.IGNORECASE
)
README_NAMES = ("README.md", "README.rst", "README.txt")
USER_AGENT = "t2-touchid-linux-external-watch/1"


class WatchError(RuntimeError):
    pass


def local_day() -> str:
    return datetime.now().astimezone().date().isoformat()


def utc_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_json(path: Path, *, required: bool) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if required:
            raise WatchError(f"required file is absent: {path}")
        return {"schema_version": 1, "sources": {}}
    except (OSError, json.JSONDecodeError) as error:
        raise WatchError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise WatchError(f"JSON root is not an object: {path}")
    return value


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", text=True
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def request_bytes(url: str, *, accept: str | None = None) -> tuple[bytes, Any]:
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    token = os.environ.get("GITHUB_TOKEN")
    if token and urllib.parse.urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read(), response.headers
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise WatchError(f"request failed for {url}: {error}") from error


def request_json(url: str) -> dict[str, Any]:
    body, _ = request_bytes(url, accept="application/vnd.github+json")
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise WatchError(f"response is not JSON for {url}: {error}") from error
    if not isinstance(value, dict):
        raise WatchError(f"response root is not an object for {url}")
    return value


def canonical_repository(owner: str, repository: str) -> str:
    return f"{owner}/{repository.removesuffix('.git')}"


def repository_links(text: str) -> list[str]:
    links = {
        canonical_repository(match.group(1), match.group(2))
        for match in GITHUB_REPOSITORY.finditer(text)
    }
    return sorted(links, key=str.casefold)


def git_remote_state(repository: str, ref: str) -> tuple[str, str]:
    url = f"https://github.com/{repository}.git"
    target = "HEAD" if ref == "HEAD" else f"refs/heads/{ref}"
    command = ["git", "ls-remote", url, target, "refs/tags/*"]
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WatchError(f"git ls-remote failed for {repository}: {error}") from error
    rows = sorted(line for line in result.stdout.splitlines() if line.strip())
    heads = [line.split()[0] for line in rows if line.split()[1] == target]
    if len(heads) != 1:
        raise WatchError(f"{repository} did not expose exactly one {target}")
    digest = hashlib.sha256("\n".join(rows).encode()).hexdigest()
    return heads[0], digest


def read_remote_readme(repository: str, commit: str) -> str | None:
    for name in README_NAMES:
        url = f"https://raw.githubusercontent.com/{repository}/{commit}/{name}"
        try:
            body, _ = request_bytes(url)
        except WatchError as error:
            if "HTTP Error 404" in str(error):
                continue
            raise
        return body.decode("utf-8", errors="replace")
    return None


def check_github_repo(source: dict[str, Any]) -> dict[str, Any]:
    repository = source["repository"]
    ref = source.get("ref", "HEAD")
    commit, refs_digest = git_remote_state(repository, ref)
    result: dict[str, Any] = {
        "commit": commit,
        "refs_digest": refs_digest,
        "ref": ref,
        "url": f"https://github.com/{repository}",
    }
    if source.get("lead_scan"):
        readme = read_remote_readme(repository, commit)
        result["repository_links"] = repository_links(readme or "")
        result["readme_present"] = readme is not None
    return result


def check_github_item(source: dict[str, Any]) -> dict[str, Any]:
    repository = source["repository"]
    number = int(source["number"])
    endpoint = "pulls" if source["kind"] == "github_pull" else "issues"
    url = f"https://api.github.com/repos/{repository}/{endpoint}/{number}"
    item = request_json(url)
    result: dict[str, Any] = {
        "state": item.get("state"),
        "title": item.get("title"),
        "updated_at": item.get("updated_at"),
        "url": item.get("html_url", f"https://github.com/{repository}/{endpoint}/{number}"),
    }
    if source["kind"] == "github_pull":
        result["merged"] = bool(item.get("merged"))
        result["merge_commit_sha"] = item.get("merge_commit_sha")
        head = item.get("head")
        result["head_sha"] = head.get("sha") if isinstance(head, dict) else None
    return result


def check_web_page(source: dict[str, Any]) -> dict[str, Any]:
    body, headers = request_bytes(source["url"])
    return {
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "etag": headers.get("ETag"),
        "last_modified": headers.get("Last-Modified"),
        "url": source["url"],
    }


def source_fingerprint(result: dict[str, Any]) -> str:
    ignored = {"checked_at", "checked_local_date"}
    stable = {key: value for key, value in result.items() if key not in ignored}
    return hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def source_key(source: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:20]


def check_source(source: dict[str, Any]) -> dict[str, Any]:
    kind = source.get("kind")
    if kind == "github_repo":
        return check_github_repo(source)
    if kind in {"github_issue", "github_pull"}:
        return check_github_item(source)
    if kind == "web_page":
        return check_web_page(source)
    raise WatchError(f"unsupported source kind: {kind!r}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--force", action="store_true", help="repeat checks made today")
    parser.add_argument("--json", action="store_true", help="emit machine-readable report")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    manifest = load_json(args.manifest, required=True)
    sources = manifest.get("sources")
    if manifest.get("schema_version") != 1 or not isinstance(sources, list):
        raise WatchError("manifest must be schema 1 with a sources array")
    state = load_json(args.state, required=False)
    if state.get("schema_version") != 1 or not isinstance(state.get("sources"), dict):
        raise WatchError("state must be schema 1 with a sources object")

    today = local_day()
    known_repositories = {
        source["repository"].casefold()
        for source in sources
        if isinstance(source, dict) and isinstance(source.get("repository"), str)
    }
    report: dict[str, Any] = {
        "local_date": today,
        "state_path": str(args.state),
        "checked": [],
        "cached": [],
        "changed": [],
        "new_leads": [],
        "errors": [],
    }

    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("name"), str):
            report["errors"].append("manifest contains an invalid source")
            continue
        key = source_key(source)
        prior = state["sources"].get(key)
        if (
            not args.force
            and isinstance(prior, dict)
            and prior.get("checked_local_date") == today
        ):
            report["cached"].append(source["name"])
            continue
        try:
            current = check_source(source)
        except (KeyError, TypeError, ValueError, WatchError) as error:
            report["errors"].append(f"{source['name']}: {error}")
            continue
        current["checked_at"] = utc_timestamp()
        current["checked_local_date"] = today
        current["fingerprint"] = source_fingerprint(current)
        report["checked"].append(source["name"])
        if isinstance(prior, dict) and prior.get("fingerprint") != current["fingerprint"]:
            report["changed"].append(
                {
                    "name": source["name"],
                    "url": current.get("url"),
                    "previous": prior.get("commit") or prior.get("updated_at") or prior.get("body_sha256"),
                    "current": current.get("commit") or current.get("updated_at") or current.get("body_sha256"),
                }
            )
        prior_links = set(prior.get("repository_links", [])) if isinstance(prior, dict) else set()
        for link in current.get("repository_links", []):
            if link.casefold() not in known_repositories and link not in prior_links:
                report["new_leads"].append(
                    {"source": source["name"], "repository": link}
                )
        state["sources"][key] = current

    state["last_run_at"] = utc_timestamp()
    if not report["errors"]:
        state["last_complete_local_date"] = today
    write_json_atomic(args.state, state)

    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"External research watch: {today}")
        print(f"checked={len(report['checked'])} cached={len(report['cached'])} "
              f"changed={len(report['changed'])} new_leads={len(report['new_leads'])} "
              f"errors={len(report['errors'])}")
        for change in report["changed"]:
            print(f"CHANGED {change['name']}: {change['previous']} -> {change['current']}")
        for lead in report["new_leads"]:
            print(f"LEAD {lead['source']}: https://github.com/{lead['repository']}")
        for error in report["errors"]:
            print(f"ERROR {error}", file=sys.stderr)
        print(f"state={args.state}")
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except WatchError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
