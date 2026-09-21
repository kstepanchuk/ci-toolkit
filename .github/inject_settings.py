#!/usr/bin/env python3
"""Fill deployment settings from environment (GitHub Actions secrets) into the source tree."""
import os
import pathlib
import sys

FILES = [
    "libs/hbb_common/src/config.rs",
    "src/common.rs",
    "Cargo.toml",
    "flutter/windows/runner/Runner.rc",
    "flutter/macos/Runner/Configs/AppInfo.xcconfig",
]
VALUES = {
    "__SDO_DOMAIN__": os.environ.get("SDO_DOMAIN", ""),
    "__SDO_KEY__": os.environ.get("SDO_KEY", ""),
    "__SDO_COMPANY__": os.environ.get("SDO_COMPANY", ""),
}
missing = [k for k, v in VALUES.items() if not v]
if missing:
    sys.exit("missing secrets for: " + ", ".join(missing))
for rel in FILES:
    p = pathlib.Path(rel)
    s = p.read_text(encoding="utf-8")
    for k, v in VALUES.items():
        s = s.replace(k, v)
    p.write_text(s, encoding="utf-8")
left = [f for f in FILES if "__SDO_" in pathlib.Path(f).read_text(encoding="utf-8")]
if left:
    sys.exit("markers left in: " + ", ".join(left))
print("settings injected")
