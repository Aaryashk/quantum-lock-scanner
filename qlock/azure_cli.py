"""The messenger: sends one question to Azure and brings back the answer.

We don't talk to Azure directly. We ask the Azure command-line tool ("az"), which is
already installed and signed in on this computer, to do it for us - like sending a
runner to the office with a written question and waiting for the filled-in form.

Only READ commands are ever sent. Nothing is created, changed or deleted.
"""

import json
import shutil
import subprocess


class AzureError(Exception):
    """Azure (or the az tool) said no, or something went wrong on the way."""


def run_az(args: list[str]):
    """Run one `az` command and return its answer as Python data (lists / dicts)."""
    az_path = shutil.which("az")
    if az_path is None:
        raise AzureError("The Azure command-line tool ('az') is not installed on this computer.")

    result = subprocess.run(
        [az_path, *args, "-o", "json", "--only-show-errors"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if result.returncode != 0:
        # Keep only the first line of Azure's complaint - it's usually the useful part.
        first_line = (result.stderr.strip().splitlines() or ["unknown error"])[0]
        raise AzureError(first_line)

    return json.loads(result.stdout) if result.stdout.strip() else None
