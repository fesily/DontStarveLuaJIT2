# DST Stress Test Bot

Multi-instance stress test framework for Don't Starve Together servers.

## Quick Start

### 1. Start a dedicated server

```bash
dontstarve_dedicated_server_nullrenderer_x64.exe -console -lan -players 32 -tick 30 -cluster MyCluster -shard Master
```

### 2. Install the mod

Copy `tests/stress_test_mod/` to DST's client mod directory:
```
%USERPROFILE%\Documents\Klei\DoNotStarveTogether\client_save\client_mods\stress_test_bot\
```

Enable it in the mod settings (or add to `modsettings.lua`).

### 3. Launch bot clients

```bash
dontstarve_steam_x64.exe +connect 127.0.0.1:11000
```

Each instance auto-bypasses the character selection lobby and spawns into the world.

### Multiple instances

Launch N instances in parallel:
```powershell
1..8 | ForEach-Object { Start-Process "dontstarve_steam_x64.exe" "+connect 127.0.0.1:11000" }
```

## Configuration

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `auto_spawn_character` | wilson, willow, wolfgang, wendy, wx78, wickerbottom, woodie, wes, random | wilson | Character to auto-spawn as |
| `auto_spawn_delay` | 0, 1, 2, 5 (seconds) | 1 | Delay before sending spawn request |

## How It Works

The mod hooks `ResumeRequestLoadComplete` (defined in `mainfunctions.lua:2027`).

When a new player connects (no existing session), the original game pushes `LobbyScreen` for character selection. This mod skips the lobby and directly calls `TheNet:SendSpawnRequestToServer()` with the configured character.

Existing sessions (reconnects) are handled normally by the original game code.

## Architecture

```
Dedicated Server (localhost, -lan -console)
    ↕ RakNet UDP
N × DST Client Instances
    └── stress_test_bot mod
        ├── +connect CLI arg → auto-connects to server
        └── hooked ResumeRequestLoadComplete → auto-spawns character
```

## Current Limitations

- Bots stand still after spawning (no behavior AI yet)
- Each bot requires a full game client instance (~1-2 GB RAM each)
- All bots use the same Steam account (may conflict; use `-lan` server to avoid auth)

## Roadmap

- [ ] Bot behavior AI (wander, gather, craft)
- [ ] Server-side metrics collection (tick time, entity count, network bandwidth)
- [ ] Automated test orchestration (launch N bots, collect metrics, report)
