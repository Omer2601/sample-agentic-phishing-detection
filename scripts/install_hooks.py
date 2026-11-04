# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Install the pre-push gate. Same as `uv run python scripts/prepush.py --install-hook`."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepush  # noqa: E402

if __name__ == "__main__":
    sys.exit(prepush.main(["--install-hook"]))
