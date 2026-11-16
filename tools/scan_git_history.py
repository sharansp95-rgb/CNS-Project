#!/usr/bin/env python3
"""Pattern-based history/working-tree secret scan; never print secret values.

Includes all refs and local reflogs. Public test keys and placeholder URLs are
reported separately. No history is rewritten and nothing is uploaded.
"""

import argparse
import base64
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PEM = re.compile(
    rb"-----BEGIN ((?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\s+[A-Za-z0-9+/=\s]{80,}-----END \1-----"
)
PATTERNS = {
    "github_token": re.compile(
        rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b"
    ),
    "aws_access_key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "provider_api_key": re.compile(
        rb"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}|rnd_[A-Za-z0-9]{24,}|xox[baprs]-[A-Za-z0-9-]{24,})\b"
    ),
}
URL = re.compile(
    rb"postgres(?:ql)?(?:\+psycopg)?://[^\s/:]+:([^\s/@]+)@([^\s/\x22\x27<>]+)"
)
PATH = re.compile(
    r"(^|/)(data|logs|exports)/|(^|/)\.env(?:$|\.)|certs/.*\.(key|crt|pem)$|\.(db|sqlite|sqlite3|key)$",
    re.I,
)


def run(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def scan():
    findings = []
    public_pems = set()
    placeholders = set()
    seen = set()
    blobs = 0
    entries = [
        line.split(" ", 1)
        for line in run("rev-list", "--objects", "--all", "--reflog")
        .decode()
        .splitlines()
        if " " in line
    ]

    def content(data, path, oid):
        matches = []
        if PEM.search(data):
            matches.append("private_key_pem")
        if data.startswith(b"SQLite format 3\0"):
            matches.append("sqlite_database")
        for name, pattern in PATTERNS.items():
            if pattern.search(data):
                matches.append(name)
        for encoded in re.findall(rb"LS0tLS1CRUdJTi[A-Za-z0-9+/=]{80,}", data):
            try:
                if PEM.search(base64.b64decode(encoded, validate=True)):
                    matches.append("base64_private_key")
            except ValueError:
                pass
        for match in URL.finditer(data):
            password, host = match.groups()
            if password.lower() in (
                b"password",
                b"placeholder",
                b"p",
                b"other",
                b"y",
            ) or host.startswith((b"localhost", b"127.0.0.1", b"db.invalid")):
                placeholders.add(path)
            else:
                matches.append("database_password_url")
        if (
            path.endswith(".pem")
            and b"-----BEGIN PUBLIC KEY-----" in data
            and not matches
        ):
            public_pems.add(path)
        for kind in set(matches):
            findings.append(dict(kind=kind, path=path, object=oid))

    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        for oid, path in entries:
            if PATH.search(path):
                findings.append(
                    dict(kind="sensitive_history_path", path=path, object=oid[:12])
                )
            if oid in seen:
                continue
            seen.add(oid)
            process.stdin.write((oid + "\n").encode())
            process.stdin.flush()
            header = process.stdout.readline().decode().split()
            if len(header) != 3:
                continue
            data = process.stdout.read(int(header[2]))
            process.stdout.read(1)
            if header[1] == "blob":
                blobs += 1
                content(data, path, oid[:12])
    finally:
        process.stdin.close()
        process.wait()
    current = (
        run("ls-files", "--cached", "--others", "--exclude-standard", "-z")
        .decode()
        .split("\0")
    )
    current_count = 0
    for path in sorted(set(current) - {""}):
        file = ROOT / path
        if file.is_file():
            current_count += 1
            if PATH.search(path):
                findings.append(
                    dict(
                        kind="sensitive_worktree_path", path=path, object="working-tree"
                    )
                )
            content(file.read_bytes(), path, "working-tree")
    return dict(
        scope="all refs, local reflogs and non-ignored working-tree files",
        reachable_commits=len(run("rev-list", "--all").splitlines()),
        commits_including_reflogs=len(
            run("rev-list", "--all", "--reflog").splitlines()
        ),
        historical_blobs=blobs,
        working_tree_files=current_count,
        public_test_pems=sorted(public_pems),
        placeholder_database_url_files=sorted(placeholders),
        sensitive_findings=findings,
        limitation="Pattern/path scan, not an exhaustive guarantee or image/PDF OCR",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report")
    args = parser.parse_args()
    result = scan()
    output = json.dumps(result, indent=2) + "\n"
    if args.report:
        Path(args.report).write_text(output)
    print(output, end="")
    raise SystemExit(1 if result["sensitive_findings"] else 0)
