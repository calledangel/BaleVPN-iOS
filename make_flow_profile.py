#!/usr/bin/env python3
"""Create a private app/relay profile from an existing FlowDriver5 authorization."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path, help="FlowDriver5 directory with an existing OAuth authorization")
parser.add_argument("output", type=Path, help="new directory for the private profile")
args = parser.parse_args()

def read(name):
    with (args.source / name).open() as source:
        return json.load(source)

config = read("client_config.json")
credentials = read("credentials.json")["installed"]
token = read("credentials.json.token")
folder = config.get("google_folder_id", "")
if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", folder):
    raise SystemExit("Set an existing Drive folder ID in client_config.json.")
if not credentials.get("client_id") or not token.get("refresh_token"):
    raise SystemExit("An existing OAuth client and refresh token are required.")
profile = {
    "folder_id": folder,
    "client_id": credentials["client_id"],
    "client_secret": credentials.get("client_secret", ""),
    "refresh_token": token["refresh_token"],
    "key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    "poll_ms": 750,
    "flush_ms": 400,
}
args.output.mkdir(mode=0o700)
path = args.output / "flowdriver.json"
with open(path, "x", opener=lambda name, flags: os.open(name, flags, 0o600)) as output:
    json.dump(profile, output, indent=2)
    output.write("\n")
print(path)
