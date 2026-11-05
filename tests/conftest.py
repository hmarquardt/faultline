import socket

import pytest

from faultline.domain import EndpointProfile
from faultline.rubrics import sample_rubric
from faultline.service import Workbench
from faultline.storage import Store


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """A stray real socket is a test failure; HTTP tests use MockTransport only."""

    def forbidden(*args, **kwargs):
        raise AssertionError("Network access is forbidden in tests")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.fixture
def workbench(tmp_path):
    return Workbench(Store(tmp_path / "history.sqlite3"))


@pytest.fixture
def profile():
    return EndpointProfile(name="Secure fixture", authorized=True)


@pytest.fixture
def rubric():
    return sample_rubric()
