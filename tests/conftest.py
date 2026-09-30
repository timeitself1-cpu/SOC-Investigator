import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from investigator.backends.fixture import FixtureBackend
from investigator.config import load_settings


@pytest.fixture(scope="session")
def cases_dir() -> Path:
    return ROOT / "investigator" / "cases"


@pytest.fixture
def settings(cases_dir):
    return load_settings(llm="mock", backend="fixture")


@pytest.fixture
def backend(cases_dir) -> FixtureBackend:
    return FixtureBackend(cases_dir)
