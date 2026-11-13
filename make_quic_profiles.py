#!/usr/bin/env python3
"""Issue a separate client and server identity for one BaleVPN pair."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile


def openssl(directory, *args):
    subprocess.run(["openssl", *args], cwd=directory, check=True, capture_output=True)


def issue_pair(destination):
    os.umask(0o077)
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="balevpn-identity-") as temporary:
        directory = Path(temporary)
        (directory / "ca.conf").write_text(
            "[req]\ndistinguished_name=dn\nx509_extensions=ca\n"
            "[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n"
            "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
        )
        openssl(directory, "genpkey", "-algorithm", "EC", "-pkeyopt",
                "ec_paramgen_curve:prime256v1", "-out", "ca-key.pem")
        openssl(directory, "req", "-x509", "-new", "-sha256", "-days", "365",
                "-config", "ca.conf", "-subj", "/CN=BaleVPN Pair CA",
                "-key", "ca-key.pem", "-out", "ca.pem")
        ca = (directory / "ca.pem").read_text()

        for role, name, usage in (("server", "lktunnel", "serverAuth"),
                                  ("iphone", "BaleVPN iPhone", "clientAuth")):
            extensions = (
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                f"extendedKeyUsage={usage}\n"
            )
            if role == "server":
                extensions += "subjectAltName=DNS:lktunnel\n"
            (directory / "leaf.conf").write_text(extensions)
            openssl(directory, "genpkey", "-algorithm", "EC", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-out", "leaf-key.pem")
            openssl(directory, "req", "-new", "-subj", f"/CN={name}",
                    "-key", "leaf-key.pem", "-out", "leaf.csr")
            openssl(directory, "x509", "-req", "-sha256", "-days", "365",
                    "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca-key.pem",
                    "-set_serial", f"0x{secrets.token_hex(16)}", "-extfile", "leaf.conf",
                    "-out", "leaf.pem")
            openssl(directory, "verify", "-purpose", "sslserver" if role == "server" else "sslclient",
                    "-CAfile", "ca.pem", "leaf.pem")
            (destination / f"{role}.json").write_text(json.dumps({
                "certificate": (directory / "leaf.pem").read_text(),
                "private_key": (directory / "leaf-key.pem").read_text(),
                "ca_certificate": ca,
            }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new private output directory")
    args = parser.parse_args()
    issue_pair(args.output)
    print(f"Created server.json and iphone.json in {args.output}")
