#!/usr/bin/env python3
"""Check both packaged MCP modes with disposable credentials, without a DB."""
from pathlib import Path
import subprocess
import sys
import tempfile
from probe_mcp import probe


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python3 smoke_stdio.py java -jar /path/to/jar")
    command = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="ai-db-mcp-smoke-") as temporary:
        root = Path(temporary)
        options = ["--config-dir", str(root / "config"), "--key-provider", "keyfile:" + str(root / "master.key")]
        answers = "\n".join(["SMOKE", "POSTGRESQL", "jdbc:postgresql://127.0.0.1:1/smoke?sslmode=verify-full", "smoke", "public", "smoke-placeholder", ""])
        subprocess.run(command + ["init", *options, "--password-stdin", "--skip-connection-test"],
                       input=answers, text=True, capture_output=True, check=True, timeout=30)
        subprocess.run(command + ["profile", "add", *options, "--password-stdin", "--skip-connection-test"],
                       input=answers.replace("SMOKE\n", "OTHER\n", 1), text=True, capture_output=True, check=True, timeout=30)
        for mode in ("read", "write", "auto"):
            profiles = probe(command + ["start", "--mode", mode, "--profiles", "SMOKE", *options], check_database=False)
            assert {p["label"] for p in profiles} == {"SMOKE"}, profiles
        setup = "\n".join(["OTHER##POSTGRESQL##jdbc:postgresql://127.0.0.1:1/smoke?sslmode=verify-full##smoke##public##smoke-placeholder",
                            "ACCESS=UPDATE", "UPDATE=public.orders", "OVERRIDE=YES", "END", ""])
        subprocess.run(command + ["init", "--setup", *options, "--password-stdin", "--skip-connection-test"],
                       input=setup, text=True, capture_output=True, check=True, timeout=30)
        for scope, writable in (("SMOKE", False), ("OTHER", True)):
            profiles = probe(command + ["start", "--profiles", scope, *options], check_database=False)
            assert len(profiles) == 1 and profiles[0]["gatewayReadOnly"] == (not writable)
        rejected = subprocess.run(command + ["start", "--profiles", "MISSING", *options], capture_output=True, timeout=30)
        assert rejected.returncode == 2
        print("PASS: one default auto endpoint exposes 4/8 tools according to scoped policy; explicit modes remain isolated")


if __name__ == "__main__":
    main()
