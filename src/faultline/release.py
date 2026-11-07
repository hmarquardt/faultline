"""Release facts and local diagnostics. No network, no credential values."""

import os
import platform
import sqlite3
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path

from faultline.scenarios import scenarios
from faultline.storage import SCHEMA_VERSION, Store
from faultline.techniques import techniques

DISTRIBUTION = "faultline-workbench"


def installed_version() -> str:
    try:
        return package_version(DISTRIBUTION)
    except PackageNotFoundError:  # pragma: no cover - editable installs still resolve
        return "unknown"


def build_facts() -> dict:
    """Version and build facts an operator can paste into a bug report."""
    return {
        "package": DISTRIBUTION,
        "version": installed_version(),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "sqlite": sqlite3.sqlite_version,
        "schema_version": SCHEMA_VERSION,
        "contracts": "1",
        "report_formats": "2.0.0, 2.1.0, 2.2.0, 2.3.0",
        "scenarios": len(scenarios()),
        "techniques": len(techniques()),
    }


def diagnose(store: Store) -> dict:
    """Check the installation, assets, database and environment handling locally."""
    problems: list[str] = []
    notes: list[str] = []
    facts = build_facts()
    if facts["version"] == "unknown":
        problems.append("package-version-unresolved")
    try:
        loaded = scenarios()
        if len(loaded) != 6:
            notes.append(f"scenario count is {len(loaded)}, expected 6")
    except Exception:  # noqa: BLE001 - diagnostics must never crash
        problems.append("scenario-assets-unreadable")
    try:
        techniques()
    except Exception:  # noqa: BLE001
        problems.append("technique-assets-unreadable")
    path = Path(store.path)
    if not path.exists():
        notes.append("database-will-be-created")
    else:
        try:
            with store.connect() as db:
                if db.execute("PRAGMA foreign_key_check").fetchall():
                    problems.append("foreign-key-violation")
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    problems.append("database-integrity-check-failed")
        except sqlite3.Error:
            problems.append("database-unreadable")
    if facts["schema_version"] != store.schema_version:
        problems.append("schema-version-mismatch")
    credential_variables = sorted(
        name for name in os.environ if name.endswith("_API_KEY") or name.endswith("_TOKEN")
    )
    # Only names are reported; values are never read or printed.
    for profile in store.profiles():
        if profile.credential_env and not os.environ.get(profile.credential_env):
            notes.append(f"credential-unresolved:{profile.id[:8]}:{profile.credential_env}")
    return {
        "version": facts["version"],
        "python": facts["python"],
        "schema_version": facts["schema_version"],
        "database": str(path),
        "database_exists": path.exists(),
        "scenarios": facts["scenarios"],
        "techniques": facts["techniques"],
        "credential_variables_present": len(credential_variables),
        "notes": "; ".join(notes) or "none",
        "problems": "; ".join(problems) or "",
    }
