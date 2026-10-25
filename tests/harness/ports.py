"""UDP port selection for game-launching tests.

The harness used to hardcode the cluster's ``server_port`` (10999). A leftover
dedicated server from an interrupted run - or the user's own server - keeps that
port bound, the next test then dies with ``RakNet UDP startup failed:
SOCKET_PORT_ALREADY_IN_USE`` and the engine asserts while shutting the failed
server down (0xC0000409), which looks like the test script itself crashed.

Picking a free port right before writing ``server.ini`` keeps parallel and
repeated runs independent of whatever else is on the machine.
"""

from __future__ import annotations

import socket

DEFAULT_SMOKE_PORT = 10999


def free_udp_port(preferred: int = DEFAULT_SMOKE_PORT, span: int = 200) -> int:
    """Return the first bindable UDP port in ``[preferred, preferred + span]``.

    Binds wildcard like RakNet does, so a port held on any interface is
    reported as taken.
    """
    for port in range(preferred, preferred + span + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.bind(("0.0.0.0", port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"no free UDP port in [{preferred}, {preferred + span}]")
