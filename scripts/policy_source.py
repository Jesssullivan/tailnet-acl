"""Compile committed Dhall inputs in isolation; expose only public-safe summaries."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SECTIONS = ("groups", "tagOwners", "acls", "grants", "ssh", "nodeAttrs", "autoApprovers", "hosts")


class PolicyError(Exception):
    """Only fixed messages and numeric status codes cross the CLI boundary."""


def canonical_digest(policy):
    try:
        encoded = json.dumps(policy, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError):
        raise PolicyError("policy cannot be canonically encoded") from None
    return hashlib.sha256(encoded).hexdigest()


def strict_json_loads(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError()
            result[key] = item
        return result
    def nonfinite(_value):
        raise ValueError()
    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError()
        return result
    try:
        return json.loads(value, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)
    except (ValueError, UnicodeError):
        raise PolicyError("JSON is malformed, duplicated, or nonfinite") from None


def require_digest(value):
    if not re.fullmatch(r"[0-9a-f]{64}", value or ""):
        raise PolicyError("expected policy digest is missing or invalid")
    return value


def require_revision(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value or "") or value == "0" * 40:
        raise PolicyError("source revision is missing, invalid, or the zero revision")
    return value


def _run(args, cwd):
    # Source tools need PATH and a locale, not GitHub/API/SOPS/OAuth credentials.
    environment = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C", "LC_ALL": "C",
                   "XDG_CACHE_HOME": str(Path(cwd) / ".cache")}
    try:
        return subprocess.run(args, cwd=cwd, env=environment, capture_output=True, check=True, timeout=45).stdout
    except (OSError, subprocess.SubprocessError):
        raise PolicyError("source lookup or compilation failed") from None


def head_revision(root=ROOT):
    return require_revision(_run(["git", "rev-parse", "HEAD"], root).decode().strip())


def check_local_imports(directory):
    """Ask Dhall's parser for immediate imports without resolving their values."""
    directory = directory.resolve()
    for source in directory.rglob("*.dhall"):
        dependencies = _run(["dhall", "resolve", "--immediate-dependencies", "--file", str(source)], directory).decode().splitlines()
        for dependency in dependencies:
            if not re.fullmatch(r"(?:\./|\.\./)[A-Za-z0-9_./-]+\.dhall", dependency):
                raise PolicyError("Dhall import is outside the supported local source contract")
            target = (source.parent / dependency).resolve()
            if not target.is_relative_to(directory) or not target.is_file():
                raise PolicyError("Dhall import escapes or is missing from the committed source tree")


def compile_revision(revision, root=ROOT):
    """Ignore working files and generated artifacts; use this exact git object."""
    require_revision(revision)
    if _run(["git", "cat-file", "-t", revision], root).strip() != b"commit":
        raise PolicyError("source revision is not a commit")
    gitdir = Path(_run(["git", "rev-parse", "--absolute-git-dir"], root).decode().strip())
    paths = _run(["git", "ls-tree", "-rz", "--name-only", revision], root).decode().split(chr(0))
    with tempfile.TemporaryDirectory(prefix="acl-compile-", dir=gitdir) as directory:
        target = Path(directory)
        for name in paths:
            if not (name.endswith(".dhall") or name == "grants.json"):
                continue
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise PolicyError("invalid source path")
            output = target / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(_run(["git", "show", revision + ":" + name], root))
        check_local_imports(target)
        try:
            policy = strict_json_loads(_run(["dhall-to-json", "--file", "policy.dhall"], target))
            grants = strict_json_loads((target / "grants.json").read_text())
        except (OSError, ValueError):
            raise PolicyError("compiled policy is malformed") from None
        if not isinstance(policy, dict) or not isinstance(grants, list):
            raise PolicyError("compiled policy has an invalid shape")
        policy["grants"] = grants
    if not all(isinstance(policy.get(k), (dict, list)) for k in SECTIONS):
        raise PolicyError("compiled policy is missing a required section")
    return policy


def public_summary(live, candidate):
    """No member names, addresses, arbitrary keys, values, or error bodies."""
    return {
        "live_sha256": canonical_digest(live),
        "candidate_sha256": canonical_digest(candidate),
        "equal": live == candidate,
        "changed_sections": [key for key in SECTIONS if live.get(key) != candidate.get(key)],
        "other_sections_changed": any(live.get(k) != candidate.get(k) for k in set(live) | set(candidate) if k not in SECTIONS),
        "section_counts": {
            key: {"live": len(live[key]) if isinstance(live.get(key), (dict, list)) else None,
                  "candidate": len(candidate[key]) if isinstance(candidate.get(key), (dict, list)) else None}
            for key in SECTIONS
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Compile exact committed source and print only its canonical digest")
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    try:
        print("candidate_sha256=" + canonical_digest(compile_revision(args.revision)))
        return 0
    except PolicyError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
