from __future__ import annotations

import socket
from functools import lru_cache

import pytest


LOCALHOST_SERVER_MODULES = {
    "tests/test_agent_trace_contract.py",
    "tests/test_live_surface_individual_commands.py",
    "tests/test_rag_service_harness.py",
    "tests/test_tool_agent_harness.py",
    "tests/test_workflow_harness.py",
}


@lru_cache(maxsize=1)
def _localhost_socket_available() -> bool:
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
    except PermissionError:
        return False
    finally:
        if sock is not None:
            sock.close()
    return True


def pytest_runtest_setup(item: pytest.Item) -> None:
    path = item.path.as_posix()
    if any(path.endswith(module) for module in LOCALHOST_SERVER_MODULES) and not _localhost_socket_available():
        pytest.skip("localhost sockets are unavailable in this sandbox")
