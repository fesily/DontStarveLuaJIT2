
import subprocess, time, pathlib, sys, os
bin64 = pathlib.Path(r"C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together\bin64")
exe = bin64 / "dontstarve_steam_x64.exe"
log = bin64 / "DontStarveInjector_client.log"
if log.exists():
    log.rename(log.with_suffix(log.suffix + f".prev_{int(time.time())}"))
print("launching", exe)
proc = subprocess.Popen([str(exe), "-debug_random_data", "-offline"], cwd=str(bin64))
print("pid", proc.pid)
# wait up to 45s or exit
for i in range(45):
    rc = proc.poll()
    if rc is not None:
        print("exited early", rc, "after", i, "s")
        break
    time.sleep(1)
else:
    print("still running after 45s")
# print logs
if log.exists():
    text = log.read_text(encoding="utf-8", errors="replace")
    print("=== injector log last 100 lines ===")
    print("\n".join(text.splitlines()[-100:]))
else:
    print("no injector log")
clog = pathlib.Path(r"C:\Users\fesil\Documents\Klei\DoNotStarveTogether\client_log.txt")
if clog.exists():
    t=clog.read_text(encoding="utf-8", errors="replace")
    print("=== client_log last 40 ===")
    print("\n".join(t.splitlines()[-40:]))
if proc.poll() is None:
    print("killing still-running process")
    proc.terminate()
    try:
        proc.wait(5)
    except Exception:
        proc.kill()
