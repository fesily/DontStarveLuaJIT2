"""Offline cluster config for harness runs.

Writes an own ``-persistent_storage_root`` tree so tests never touch the user's
``Documents/Klei`` (Windows) / ``~/.klei`` (Linux) clusters. ``shard_enabled``
stays false and no ``master_ip`` is set, so a single Master shard boots without
gateway/shard-master lookups.

No ``modoverrides.lua`` / ``dedicated_server_mods_setup.lua``: mod enabling is
env-only (``force_enable_mods``) so an injector/force-enable failure cannot be
masked by a config file.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

DEFAULT_CLUSTER = "DsHarnessThrow"
DEFAULT_SHARD = "Master"
DEFAULT_SERVER_PORT = 11998

_CLUSTER_INI = """[GAMEPLAY]
game_mode = survival
max_players = 1
pvp = false
pause_when_empty = true
vote_enabled = false

[NETWORK]
cluster_intention = cooperative
cluster_name = {cluster}
cluster_description = harness
cluster_password =
offline_server = true
tick_rate = 15

[MISC]
max_snapshots = 2
console_enabled = true

[SHARD]
shard_enabled = false
"""

_SERVER_INI = """[SHARD]
is_master = true
name = {shard}

[NETWORK]
server_port = {server_port}

[ACCOUNT]
encode_user_path = true
"""


def write_offline_cluster(
    persist_root: Path,
    cluster: str = DEFAULT_CLUSTER,
    shard: str = DEFAULT_SHARD,
    server_port: int = DEFAULT_SERVER_PORT,
) -> Path:
    """Create ``<root>/DoNotStarveTogether/<cluster>/<shard>/`` config files.

    Returns the ``server_log.txt`` path the dedicated server will write (the
    file itself may not exist yet).
    """
    shard_dir = persist_root / "DoNotStarveTogether" / cluster / shard
    shard_dir.mkdir(parents=True, exist_ok=True)
    (shard_dir.parent / "cluster.ini").write_text(
        _CLUSTER_INI.format(cluster=cluster), encoding="utf-8"
    )
    (shard_dir / "server.ini").write_text(
        _SERVER_INI.format(shard=shard, server_port=server_port), encoding="utf-8"
    )
    return shard_dir / "server_log.txt"


def remove_persist_tree(persist_root: Path, attempts: int = 5, delay: float = 0.3) -> bool:
    """Delete an isolated persist tree, retrying to outlive handle release.

    A game process that is killed by a fault can still hold its log/minidump
    handles for a moment, which makes a single ``rmtree`` fail halfway. Returns
    False (and prints the path) when the tree survives every attempt.
    """
    for _ in range(attempts):
        shutil.rmtree(persist_root, ignore_errors=True)
        if not persist_root.exists():
            return True
        time.sleep(delay)
    print(f"[harness] WARN: persist tree still present: {persist_root}")
    return False
