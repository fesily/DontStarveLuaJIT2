
import subprocess, time, pathlib, os, sys
bin64 = pathlib.Path(r"C:\Program Files (x86)\Steam\steamapps\common\Don't Starve Together\bin64")
exe = bin64 / "dontstarve_steam_x64.exe"
log = bin64 / "DontStarveInjector_client.log"
err = bin64 / "inject_stderr.txt"
if log.exists():
    log.rename(log.with_suffix(log.suffix + f".prev_{int(time.time())}"))
if err.exists():
    err.unlink()
print("launching DEBUG", exe)
# capture stderr to file (fprintf goes there if we redirect)
with open(err, "w", encoding="utf-8", errors="replace") as ef:
    proc = subprocess.Popen(
        [str(exe), "-debug_random_data", "-offline"],
        cwd=str(bin64),
        stderr=ef,
        stdout=subprocess.DEVNULL,
    )
print("pid", proc.pid)
for i in range(20):
    rc = proc.poll()
    if rc is not None:
        print("exited", rc, "after", i, "s")
        break
    time.sleep(1)
else:
    print("still running 20s")
if log.exists():
    text = log.read_text(encoding="utf-8", errors="replace")
    print("=== injector log ===")
    print(text)
else:
    print("no injector log")
if err.exists():
    print("=== stderr ===")
    print(err.read_text(encoding="utf-8", errors="replace")[-4000:])
clog = pathlib.Path(r"C:\Users\fesil\Documents\Klei\DoNotStarveTogether\client_log.txt")
if clog.exists():
    t=clog.read_text(encoding="utf-8", errors="replace")
    print("=== client last 20 ===")
    print("\n".join(t.splitlines()[-20:]))
if proc.poll() is None:
    proc.terminate()
    try: proc.wait(5)
    except Exception: proc.kill()
