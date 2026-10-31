#!/usr/bin/env python3
"""Host-side smoke test for a disposable macOS `container` Linux VM (JAR mounted at /bundle)."""
import concurrent.futures
import subprocess
import sys
import uuid
from probe_mcp import probe

name = sys.argv[1]
home = "/tmp/dbmcp-smoke-" + uuid.uuid4().hex
subprocess.run(["container", "exec", name, "mkdir", "-p", home], check=True, timeout=30)
base = ["container", "exec", "-i", "--env", "HOME=" + home, name,
        "java", "-Duser.home=" + home, "-jar", "/bundle/ai-db-mcp.jar"]
answers = "\n".join(["LINUX-SMOKE", "POSTGRESQL", "jdbc:postgresql://127.0.0.1:1/smoke?sslmode=verify-full",
                       "smoke", "public", "CONTAINER-PASSWORD-SENTINEL", ""])

def cli(args, input=None, okay=True):
    result = subprocess.run(base + args, input=input, capture_output=True, text=True, timeout=60)
    assert "CONTAINER-PASSWORD-SENTINEL" not in result.stdout + result.stderr, "credential leaked"
    assert "LogManager accessed before" not in result.stderr, "logging initialized too late"
    if okay and result.returncode:
        raise RuntimeError("CLI failed: " + " ".join(args[:2]) + "\n" + result.stderr)
    return result

def shell(command):
    return subprocess.check_output(["container", "exec", "--env", "HOME=" + home, name,
                                    "/bin/sh", "-c", command], text=True, timeout=30).strip()

initialized = cli(["init", "--password-stdin", "--skip-connection-test"], answers)
assert "Linux key file" in initialized.stderr, initialized.stderr
permissions = shell('stat -c "%a" "$HOME/.config/dbmcp"; stat -c "%a" "$HOME"/.config/dbmcp/*.key')
assert permissions.splitlines() == ["700", "600"], permissions
assert "LINUX-SMOKE" in cli(["profile", "list"]).stdout
print("PASS " + name + ": first init without desktop/Secret Service; fallback directory 0700, key 0600; restart decrypts")
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
    jobs = [workers.submit(probe, base + ["start", "--profiles", "LINUX-SMOKE"], check_database=False) for _ in range(2)]
    for job in jobs:
        assert {p["label"] for p in job.result()} == {"LINUX-SMOKE"}
print("PASS " + name + ": two independent MCP processes initialize and expose four read tools")
original = shell('sha256sum "$HOME/.config/ai-db-mcp/profiles.enc"').split()[0]
shell('for key in "$HOME"/.config/dbmcp/*.key; do mv "$key" "$key.held"; done')
try:
    failed = cli(["init", "--password-stdin", "--skip-connection-test"], answers, okay=False)
    assert failed.returncode != 0, "lost key was silently replaced"
    assert "Diagnostic trace" in failed.stderr and "Caused by:" in failed.stderr
    assert shell('find "$HOME/.config/dbmcp" -name "*.key"').strip() == ""
    assert original == shell('sha256sum "$HOME/.config/ai-db-mcp/profiles.enc"').split()[0]
finally:
    shell('for key in "$HOME"/.config/dbmcp/*.key.held; do mv "$key" "${key%.held}"; done')
assert "LINUX-SMOKE" in cli(["profile", "list"]).stdout
print("PASS " + name + ": lost-key init fails with diagnostic stack; no replacement key or ciphertext changes")
# A second config must get another key even with a dead DBus address.
broken = [*base[:3], "--env", "DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/nonexistent-dbmcp-bus", *base[3:]]
second = subprocess.run(broken + ["init", "--config-dir", home + "/second-config", "--password-stdin",
                                "--skip-connection-test"], input=answers, capture_output=True, text=True, timeout=60)
assert second.returncode == 0, second.stderr
assert "Linux key file" in second.stderr
assert shell('find "$HOME/.config/dbmcp" -name "*.key" | wc -l').strip() == "2"
print("PASS " + name + ": unavailable DBus uses fallback; separate configuration gets independent key")
