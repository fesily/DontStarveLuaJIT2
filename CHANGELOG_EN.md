# Changelog

## 2.8.0

- Added LuaJIT Gen GC support (generational GC, frame GC, disabled Full GC).
- Added game fork save support.
- Added a new vertex buffer (VB) pool.
- Added buffer pool statistics tracking with EMA hit rate.
- Updated Linux signatures.
- Fixed Linux recursive crash.
- Fixed lua-debug mode.
- Renamed local server config directory.
- Fixed profiler_push signature.

## 2.7.3

- Moved SlowTaICall checker to the C side.

## 2.7.2

- Fixed network simulator (netsim) bugs.

## 2.7.1

- Fixed GameLuaModule-related bugs.

## 2.7.0

- Added client-side render vertex caching.
- Added server-side lag compensation.
- Added a network packet loss simulator.
- Added a stress-test bot framework.
- Added visual disable support for mod configuration options.
- Injected platform environment into modinfo.
- Fixed network optimization bugs.
- Fixed handling for invalid configuration file reads.