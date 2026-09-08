#!/usr/bin/env python3
"""Draft rerun check for the Ahmyth family rule report.

Downloads the public sample to a temp directory, fails if SHA256 does not
match the pinned value, expects the pinned quark-rules commit, runs quark,
and compares the 100% confidence rule-id set to the set recorded in this
prep run. Does not vendor the APK.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

SOURCE_URL = (
    "https://github.com/quark-engine/apk-samples/raw/master/malware-samples/Ahmyth.apk"
)
PINNED_SHA256 = "f39b1a25c299ff532df840c6216fee41c8eb70787aba5e51624aae7b8eccc12c"
PINNED_RULES_COMMIT = "a9fb558fae4c9d23f325289396c06d7c5e519318"
RULES_ARCHIVE_URL = (
    "https://github.com/quark-engine/quark-rules/archive/"
    f"{PINNED_RULES_COMMIT}.zip"
)
# Actual 100% confidence hits from the recorded quark run. Not guessed.
EXPECTED_HIT_IDS = {
    "00001",
    "00002",
    "00004",
    "00005",
    "00007",
    "00008",
    "00009",
    "00010",
    "00011",
    "00012",
    "00013",
    "00014",
    "00015",
    "00017",
    "00019",
    "00026",
    "00029",
    "00077",
    "00108",
    "00115",
    "00157",
    "00182",
    "00185",
    "00186",
    "00187",
    "00188",
    "00189",
    "00191",
    "00192",
    "00193",
    "00194",
    "00195",
    "00196",
    "00197",
    "00198",
    "00199",
    "00201",
    "00212",
    "00230",
    "00269",
    "00272",
    "00276",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def download(url: str, dest: Path) -> None:
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            dest.write_bytes(response.read())
    except Exception as exc:  # noqa: BLE001 — report the blocker, do not invent data
        fail(f"download failed for {url}: {exc}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rules_dir_commit(rules_dir: Path) -> str | None:
    """Return the git commit if rules_dir is inside a checkout. Does not clone."""
    probe = rules_dir
    if probe.name == "rules":
        probe = probe.parent
    git_dir = probe / ".git"
    if not git_dir.exists():
        # Archive extracts are named quark-rules-<commit>/rules
        name = probe.name
        prefix = "quark-rules-"
        if name.startswith(prefix) and len(name) > len(prefix):
            return name[len(prefix) :]
        return None
    result = subprocess.run(
        ["git", "-C", str(probe), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"could not read rules commit from {probe}: {result.stderr.strip()}")
    return result.stdout.strip()


def fetch_pinned_rules(dest_parent: Path) -> Path:
    archive = dest_parent / "quark-rules.zip"
    download(RULES_ARCHIVE_URL, archive)
    try:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest_parent)
    except zipfile.BadZipFile as exc:
        fail(f"rules archive is not a zip: {exc}")
    rules = dest_parent / f"quark-rules-{PINNED_RULES_COMMIT}" / "rules"
    if not rules.is_dir():
        fail(f"pinned rules directory missing after extract: {rules}")
    return rules


def hit_ids_from_quark_json(report_path: Path) -> set[str]:
    try:
        payload = json.loads(report_path.read_text())
    except json.JSONDecodeError as exc:
        fail(f"quark JSON is not valid: {exc}")
    crimes = payload.get("crimes")
    if not isinstance(crimes, list):
        fail("quark JSON has no crimes list")
    hits = set()
    for crime in crimes:
        if str(crime.get("confidence", "")).strip() != "100%":
            continue
        rule = str(crime.get("rule") or "")
        rule_id = Path(rule).stem
        if not rule_id:
            fail(f"100% crime missing rule filename: {crime!r}")
        hits.add(rule_id)
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rules-dir",
        type=Path,
        help="Existing quark-rules rules directory. Commit must equal the pin.",
    )
    parser.add_argument(
        "--quark",
        default=os.environ.get("QUARK_BIN", "quark"),
        help="quark executable (default: quark or $QUARK_BIN)",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="ahmyth-check-") as tmp:
        tmp = Path(tmp)
        apk = tmp / "Ahmyth.apk"
        download(SOURCE_URL, apk)
        digest = sha256_file(apk)
        if digest != PINNED_SHA256:
            fail(f"SHA256 mismatch: got {digest}, expected {PINNED_SHA256}")

        if args.rules_dir:
            rules_dir = args.rules_dir
            if not rules_dir.is_dir():
                fail(f"rules directory does not exist: {rules_dir}")
            commit = rules_dir_commit(rules_dir)
            if commit != PINNED_RULES_COMMIT:
                fail(
                    "rules commit is not the pinned commit: "
                    f"got {commit!r}, expected {PINNED_RULES_COMMIT}"
                )
        else:
            rules_dir = fetch_pinned_rules(tmp)

        report_path = tmp / "report.json"
        command = [
            args.quark,
            "-a",
            str(apk),
            "-r",
            str(rules_dir),
            "-o",
            str(report_path),
            "--core-library",
            "dextrace",
        ]
        result = subprocess.run(command, check=False)
        if result.returncode != 0 or not report_path.is_file():
            fail(f"quark failed (exit {result.returncode})")

        actual = hit_ids_from_quark_json(report_path)
        missing = sorted(EXPECTED_HIT_IDS - actual)
        unexpected = sorted(actual - EXPECTED_HIT_IDS)
        if missing or unexpected:
            fail(
                "hit rule id set mismatch: "
                f"missing={missing} unexpected={unexpected}"
            )

    print(
        "OK: sha256 matched, rules commit "
        f"{PINNED_RULES_COMMIT}, hit ids matched ({len(EXPECTED_HIT_IDS)})"
    )


if __name__ == "__main__":
    main()
