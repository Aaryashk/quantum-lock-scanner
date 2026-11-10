"""The front door of the program.

    python -m qlock --demo                  scan a pretend company (no Azure needed)
    python -m qlock --azure                 look (read-only) at your signed-in Azure subscription
    python -m qlock --host example.com      check one website's door (no Azure needed)
"""

import argparse
import sys

from qlock.azure_cli import AzureError, run_az
from qlock.azure_scan import find_web_doors, scan_azure
from qlock.doors import find_openssl, inspect_doors, make_runner
from qlock.report import build_report
from qlock.sample_data import DEMO_COMPANY, DEMO_LOCKS

NO_OPENSSL = ("Doors not checked: needs OpenSSL 3.5 or newer (it comes with Git for Windows "
              "in C:\\Program Files\\Git\\usr\\bin).")


def check_doors(hosts: list[str]):
    if not hosts:
        return [], []
    openssl = find_openssl()
    if openssl is None:
        return [], [NO_OPENSSL]
    print(f"Checking {len(hosts)} door(s)...")
    return inspect_doors(hosts, make_runner(openssl))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="qlock",
        description="Find encryption ('locks') and judge whether quantum computers could break them.",
    )
    parser.add_argument("--demo", action="store_true", help="scan a pretend company (no Azure needed)")
    parser.add_argument("--azure", action="store_true", help="look (read-only) at your signed-in Azure subscription")
    parser.add_argument("--host", action="append", default=[], metavar="ADDRESS",
                        help="check a website's door, e.g. --host example.com (can repeat)")
    args = parser.parse_args()

    if args.demo:
        print(build_report(DEMO_COMPANY, DEMO_LOCKS))
        return

    if not (args.azure or args.host):
        parser.print_help()
        return

    locks, notes, title = [], [], "websites"
    if args.azure:
        try:
            subscription = run_az(["account", "show"]).get("name", "?")
            print(f"Looking (read-only) at Azure subscription '{subscription}'...")
            locks, notes = scan_azure()
            hosts = find_web_doors()
        except AzureError as err:
            print(f"Could not talk to Azure: {err}")
            print("Tip: run  az login  to sign in, then try again.")
            sys.exit(1)
        title = f"Azure subscription '{subscription}'"
    else:
        hosts = []

    door_locks, door_notes = check_doors(list(dict.fromkeys(hosts + args.host)))
    print()
    print(build_report(title, locks + door_locks, notes + door_notes))


if __name__ == "__main__":
    main()
