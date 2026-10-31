#!/usr/bin/env python3
"""Package the verified uber-jar. No credentials or workstation config are included."""
import hashlib
import argparse
from pathlib import Path
import shutil
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bundled-db2", action="store_true", help="Require bundled JCC and label this internal distribution")
args = parser.parse_args()
module = Path(__file__).resolve().parents[1]
jar = module / "target/mcp-server-jdbc-999-SNAPSHOT.jar"
if not jar.is_file():
    raise SystemExit("Build first: ./mvnw -pl jdbc -am verify")
with zipfile.ZipFile(jar) as built:
    bundled_db2 = "com/ibm/db2/jcc/DB2Driver.class" in built.namelist()
if bundled_db2 != args.bundled_db2:
    raise SystemExit("JCC contents do not match packaging mode. Rebuild with/without -Pbundle-db2, "
                     "then use --bundled-db2 for the bundled build.")
archive = module / ("target/dbmcp-local-db2.zip" if bundled_db2 else "target/dbmcp-local.zip")
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
    files = [(jar, "lib/ai-db-mcp.jar"),
             (module / "onboarding.sh", "onboarding.sh"),
             (module / "sample.yaml", "sample.yaml"),
             (module / "setup.example.txt", "setup.example.txt"),
             (module / "setup-update.example.txt", "setup-update.example.txt"),
             (module / "setup-sql.example.txt", "setup-sql.example.txt"),
             (module / "setup-combined.example.txt", "setup-combined.example.txt"),
             (module / "bin/ai-db-mcp", "bin/ai-db-mcp"),
             (module / "bin/ai-db-mcp.cmd", "bin/ai-db-mcp.cmd"),
             (module.parent / "LICENSE", "LICENSE"),
             (module / "README.md", "README.md")]
    files += [(p, "docs/" + p.name) for p in sorted((module / "docs").glob("*.md"))]
    files += [(module / "scripts/smoke_stdio.py", "scripts/smoke_stdio.py")]
    files += [(module / ("scripts/" + name), "scripts/" + name)
              for name in ("probe_mcp.py", "onboarding_check.py", "register_defaults.py")]
    for source, name in files:
        info = zipfile.ZipInfo.from_file(source, "dbmcp/" + name)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o100755 if name in {"bin/ai-db-mcp", "onboarding.sh"} else 0o100644) << 16
        with source.open("rb") as src, output.open(info, "w") as dst:
            shutil.copyfileobj(src, dst)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_suffix(".zip.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
print(archive)
print("SHA-256:", digest)
