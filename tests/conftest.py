"""Shared test environment.

The Host allowlist rejects unknown Host headers by design. TestClient uses
``testserver``, so allow it here without weakening the production default.
"""

import os

os.environ.setdefault(
    "BREADCRUMB_ALLOWED_HOSTS",
    "testserver,127.0.0.1,localhost",
)
