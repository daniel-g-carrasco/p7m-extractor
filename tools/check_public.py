#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the tracked snapshot of a public project. No network or dependencies."""
import re
import subprocess
import sys

HOME_PATH = re.compile(r"(?:[a-z]:[/\\]+users[/\\]+[^/\\\s<>$%]+|/home/[\w.-]+|/[v]ar/home/|(?<!\w)i:[/\\])", re.IGNORECASE)
EMAIL = re.compile(r"[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
SECRETS = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----"
    r"|(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{16,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}"
    r"|glpat-[\w-]{20,}|AIza[\w-]{35}|sk_live_[A-Za-z0-9]{16,})"
)
ASSIGNMENT = re.compile(
    r"""(?ix)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret[_-]?key)["']?\s*[:=]\s*"""
    r"""["']([a-z0-9+/_=.@!-]{8,})["']"""
)


ENV_SECRET = re.compile(
    r"(?i)^\s*(?:export\s+)?(?:[a-z0-9]+_)*(?:api_key|token|password|secret|access_key)"
    r"\s*=\s*[a-z0-9+/_.=@!-]{8,}\s*(?:#.*)?$"
)
URL_SECRET = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb)://[^/\s:@]+:[^/\s@$]+@")


def category(line, public):
    if HOME_PATH.search(line):
        return "personal path"
    if SECRETS.search(line) or ASSIGNMENT.search(line) or ENV_SECRET.search(line) or URL_SECRET.search(line):
        return "possible credential"
    for address in EMAIL.findall(line):
        address = address.casefold()
        domain = address.split("@", 1)[1]
        if domain in {"example.com", "example.net", "example.org", "users.noreply.github.com"}:
            continue
        if domain.endswith((".invalid", ".test", ".example")) or address in public:
            continue
        return "unlisted email"
    return None


def decode(blob):
    if blob.startswith((b"\xff\xfe", b"\xfe\xff")):
        return blob.decode("utf-16", "replace")
    if b"\0" in blob:
        return ""
    return blob.decode("utf-8-sig", "replace")


def scan():
    records = subprocess.check_output(["git", "ls-files", "--stage", "-z", "--", "."]).split(b"\0")
    files = []
    public = set()
    for record in filter(None, records):
        header, path = record.split(b"\t", 1)
        mode, oid, stage = header.split()
        if stage != b"0":
            raise ValueError("unmerged index")
        name = path.decode("utf-8", "replace")
        if name == ".public-emails":
            items = subprocess.check_output(["git", "cat-file", "blob", oid]).decode().splitlines()
            for item in filter(None, items):
                if not EMAIL.fullmatch(item):
                    raise ValueError("invalid public email declaration")
                public.add(item.casefold())
        files.append((name, mode, oid))

    failed = False
    with subprocess.Popen(["git", "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        try:
            for name, mode, oid in files:
                label = category(name, public)
                safe_name = ascii(name)
                if label:
                    safe_name = "<redacted filename>"
                    print(f"{safe_name} ({oid[:12].decode()}): {label}")
                    failed = True
                if mode == b"160000":
                    continue
                proc.stdin.write(oid + b"\n")
                proc.stdin.flush()
                actual, kind, size = proc.stdout.readline().split()
                if actual != oid or kind != b"blob":
                    raise ValueError("unexpected Git object")
                blob = proc.stdout.read(int(size))
                if proc.stdout.read(1) != b"\n":
                    raise ValueError("incomplete Git object")
                for number, line in enumerate(decode(blob).splitlines(), 1):
                    label = category(line, public)
                    if label:
                        print(f"{safe_name}:{number}: {label}")
                        failed = True
        finally:
            proc.stdin.close()
            proc.stdout.close()
    if proc.returncode:
        raise ValueError("Git could not read the snapshot")
    print(f"Checked {len(files)} tracked entries.")
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(scan())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        sys.exit(f"Cannot check snapshot ({type(exc).__name__}).")
