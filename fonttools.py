#!/usr/bin/env python3
"""Website status checker.

Checks a list of websites and reports UP/DOWN status.
"""

import requests

status_dict = {}
# sample websites
websites = []


def check_websites(sites):
    for item in sites:
        website = item.strip()
        status = requests.get(website).status_code
        status_dict[website] = "UP" if status == 200 else "DOWN"
    print({"Website": "Status"})
    print("\n")
    print(status_dict)


if __name__ == "__main__":
    check_websites(websites)
