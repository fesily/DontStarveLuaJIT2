#!/usr/bin/env python3
"""Performance measurement contracts; no game is launched."""
from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import math
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("game_performance", Path(__file__).with_name("run.py"))
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)
import analyze
import etw_analysis
import symbol_map
import startup_etw
import etw_cpu
import crash_dumps
import server_load
import run_report


class MeasurementTest(unittest.TestCase):
    def test_ready_line_is_published_after_observer_completion(self):
        process = perf.smoke.LogProcess("fixture")
        process.started_at = 100
        completed = []

        def observe(current, at, line):
            self.assertNotIn(line, current.lines)
            completed.append(at)

        process.on_observe = observe
        with patch.object(perf.smoke.time, "perf_counter", return_value=102):
            process.observe("WORLD_READY")
        self.assertEqual(completed, [102])
        self.assertEqual(process.elapsed_until("WORLD_READY"), 2)

    def test_observer_failure_marks_fatal_without_losing_log_output(self):
        process = perf.smoke.LogProcess("fixture")

        def fail(*args):
            raise OSError("clock failed")

        process.on_observe = fail
        process.observe("first")
        process.observe("second")
        self.assertTrue(process.fatal)
        self.assertIn("clock failed", process.observation_error)
        self.assertEqual(process.lines, ["first", "second"])

    def test_dump_collection_keeps_relative_names_and_ignores_empty_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            persist = root / "persist"
            for sub in ("Master", "client"):
                (persist / sub).mkdir(parents=True)
                (persist / sub / "same.DMP").write_bytes(sub.encode())
            (persist / "empty.dmp").touch()
            (persist / "small.mdmp").write_bytes(b"mini")
            (persist / "server.log").write_bytes(b"not a dump")
            copies, errors = crash_dumps.collect_dumps(persist, root / "keep")
            self.assertFalse(errors)
            self.assertEqual(len(copies), 3)
            self.assertEqual((root / "keep/Master/same.DMP").read_bytes(), b"Master")
            self.assertEqual((root / "keep/client/same.DMP").read_bytes(), b"client")

    def test_dump_copy_failure_retains_source_and_reports_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            persist = root / "persist"
            persist.mkdir()
            dump = persist / "crash.dmp"
            dump.write_bytes(b"evidence")
            with patch.object(crash_dumps.shutil, "copy2", side_effect=OSError("disk full")):
                copied, errors = crash_dumps.collect_dumps(persist, root / "keep")
            self.assertEqual(copied, [])
            self.assertIn("disk full", errors[0])
            self.assertEqual(dump.read_bytes(), b"evidence")

    def test_server_loop_stops_on_verification_error_and_preserves_failed_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            persist = root / "persist"
            persist.mkdir()
            (persist / "crash.dmp").write_bytes(b"evidence")
            stopped = []

            def stop(**kwargs):
                stopped.append(kwargs)
                return 0

            server = SimpleNamespace(
                proc=SimpleNamespace(pid=42), fatal=False, lines=["[ds_perf] SAVE_LOADED entities=1"],
                elapsed_until=lambda marker: 1.5, stop=stop)
            args = SimpleNamespace(
                rounds=1, port_base=12010, cluster_source=root, lua=root / "luajit.exe",
                injector=root / "Injector.dll", jit="on", vm=root / "vm.dll", extra_lua="",
                timeout=1, stop_mode="shutdown", dump_dir=root / "dumps",
                output=root / "batch.json", log_dir=root / "logs")
            with patch.object(server_load.tempfile, "mkdtemp", return_value=str(persist)), \
                    patch.object(server_load, "prepare"), \
                    patch.object(perf.smoke, "start_dedicated", return_value=server), \
                    patch.object(perf.smoke, "wait_dedicated_ready", return_value=True), \
                    patch.object(server_load.perf, "module_confirmed", return_value=True), \
                    patch.object(server_load.stress, "verify_mode", side_effect=RuntimeError("wrong JIT")), \
                    patch.object(crash_dumps.shutil, "copy2", side_effect=OSError("disk full")), \
                    patch.object(server_load.perf, "remove_persist_tree") as remove, \
                    patch.object(server_load, "_results", []), \
                    contextlib.redirect_stdout(io.StringIO()):
                server_load.run_instance(0, args, root, [])
                record = server_load._results[0]
            self.assertEqual(len(stopped), 1)
            self.assertFalse(record["success"])
            self.assertIn("wrong JIT", record["error"])
            self.assertEqual(record["preserved_persist"], str(persist))
            self.assertTrue(record["dump_collection_errors"])
            remove.assert_not_called()

    def test_load_report_ignores_summary_and_diagnostic_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "console.log"
            path.write_text(
                '[load] srv0 {"round":0,"success":true}\n'
                '[load] srv0 DUMP path.dmp\n'
                '[load] SUMMARY {"runs":[{"round":0}]}\n', encoding="utf-8")
            self.assertEqual(run_report.load_records(path), [{"round": 0, "success": True}])

    def test_startup_export_does_not_cache_failed_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            etl = Path(directory) / "fixture.etl"
            etl.write_bytes(b"etl")
            receipt = etl.with_suffix(".startup-export.json")
            receipt.write_text('{"old":true}')
            decoded = {"markers": [
                {"kind": "STARTUP_LAUNCHED", "trace_us": 0},
                {"kind": "STARTUP_READY", "trace_us": 10}]}
            with patch.object(startup_etw, "tool_path", return_value="xperf"), \
                    patch.object(startup_etw.subprocess, "run"):
                with self.assertRaisesRegex(RuntimeError, "empty export"):
                    startup_etw.export({"etl_path": str(etl)}, decoded, with_samples=True)
            self.assertFalse(receipt.exists())

    def test_csv_crosscheck_requests_an_export_with_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "capture.json"
            metadata.write_text(json.dumps({
                "error": None, "etl_path": str(Path(directory) / "fixture.etl"),
                "targets": [{"pid": 42}]}))
            with patch.object(startup_etw, "read_symbols", return_value={}), \
                    patch.object(startup_etw, "export", side_effect=RuntimeError("stop")) as export:
                with self.assertRaisesRegex(RuntimeError, "stop"):
                    startup_etw.analyze(metadata, validate_csv=True)
                self.assertTrue(export.call_args.kwargs["with_samples"])

    def test_kernel_cpu_uses_thread_lifetimes_and_stack_trigger_qpc(self):
        import ctypes as ct
        import struct
        records = []

        def emit(provider, opcode, at, payload):
            data = ct.create_string_buffer(payload)
            descriptor = bytearray(16)
            descriptor[5] = opcode
            header = SimpleNamespace(ProviderId=provider, EventDescriptor=descriptor)
            records.append((SimpleNamespace(EventHeader=header, UserData=ct.addressof(data),
                                             UserDataLength=len(payload)), at, data))

        for kind, raw in (("STARTUP_LAUNCHED", 100000), ("STARTUP_READY", 300000)):
            emit(etw_cpu.PROVIDER.bytes_le, 0, raw,
                 ("DSPERF " + json.dumps({"pid": 42, "kind": kind}) + "\0").encode("utf-16-le"))
        emit(etw_cpu.THREAD, 1, 110000, struct.pack("<II", 42, 7))
        emit(etw_cpu.PERF, 46, 120000, struct.pack("<QIHH", 0x1000, 7, 3, 0))
        emit(etw_cpu.STACK, 32, 120050, struct.pack("<QIIQ", 120000, 42, 7, 0x1000))
        emit(etw_cpu.STACK, 32, 120070, struct.pack("<QIIQ", 120000, 42, 7, 0x2000))
        emit(etw_cpu.PERF, 46, 130000, struct.pack("<QIHH", 0x1100, 7, 1, 0))
        emit(etw_cpu.THREAD, 2, 140000, struct.pack("<II", 42, 7))
        emit(etw_cpu.PERF, 46, 140100, struct.pack("<QIHH", 0x1200, 7, 2, 0))
        emit(etw_cpu.STACK, 32, 140120, struct.pack("<QIIQ", 140100, 42, 7, 0x1200))
        emit(etw_cpu.THREAD, 1, 150000, struct.pack("<II", 99, 7))
        emit(etw_cpu.PERF, 46, 160000, struct.pack("<QIHH", 0x1000, 7, 5, 0))
        emit(etw_cpu.THREAD, 2, 170000, struct.pack("<II", 99, 7))
        emit(etw_cpu.PERF, 46, 170100, struct.pack("<QIHH", 0x1300, 7, 7, 0))
        emit(etw_cpu.STACK, 32, 170120, struct.pack("<QIIQ", 170100, 99, 7, 0x1300))

        def consume(path, callback, raw_timestamps):
            self.assertTrue(raw_timestamps)
            for record, at, _ in sorted(records, key=lambda row: row[1]):
                callback(record, at)
            return {"frequency": 10000000}

        markers = [{"pid": 42, "kind": kind, "trace_us": at}
                   for kind, at in (("STARTUP_LAUNCHED", 10000), ("STARTUP_READY", 30000))]
        with patch.object(etw_cpu, "consume", side_effect=consume):
            result = etw_cpu.read_cpu(Path("fixture.etl"), {42}, markers)
        samples = result["samples"][42]
        self.assertEqual(len(samples), 3)
        self.assertEqual(sum(s["weight"] for s in samples), 6)
        self.assertEqual(samples[0]["trace_us"], 12000)
        self.assertEqual([s["address"] for s in samples[0]["stack"]], [0x1000, 0x2000])
        self.assertFalse(samples[1]["stack"])
        self.assertEqual(samples[2]["address"], 0x1200)

    def test_native_jit_method_decode_and_address_reuse(self):
        import struct
        payload = struct.pack("<QQQIHHQII", 10, 0x1000, 64, 1, 0, 0, 100, 25, 0)
        payload += "LuaJIT::TRACE_1::scripts/main.lua:25\0".encode("utf-16-le")
        first = startup_etw.decode_method(payload)
        second = dict(first, method_id=2, source=101, name="second")
        other_context = dict(first, context=11, method_id=3, source=102)
        events = [
            dict(first, trace_us=10, event_id=9),
            dict(first, trace_us=11, event_id=5),
            dict(first, trace_us=20, event_id=10),
            dict(second, trace_us=30, event_id=9),
            dict(other_context, trace_us=31, event_id=9),
            {"trace_us": 40, "event_id": 12, "context": 10},
        ]
        methods = startup_etw.lifetimes(events)
        self.assertEqual(len(methods), 3)
        self.assertEqual(first["line"], 25)
        self.assertEqual([(m["begin_us"], m["end_us"]) for m in methods],
                         [(10, 20), (30, 40), (31, float("inf"))])
        samples = [{"trace_us": at, "tid": 7, "address": 0x1010,
                    "location": "Unknown!0x1010", "weight": 1, "stack": []}
                   for at in (9, 15, 25, 35, 45)]
        markers = [
            {"pid": 42, "kind": "STARTUP_LAUNCHED", "trace_us": 8, "elapsed_seconds": 0},
            {"pid": 42, "kind": "STARTUP_READY", "trace_us": 50},
        ]
        summary = startup_etw.summarize(samples, methods[:2], [], [], "", markers,
                                        {"pid": 42, "name": "dedicated"})
        modules = {m["module"]: m["weight"] for m in summary["process"]["modules"]}
        self.assertEqual(modules, {"<unresolved>": 3, "JIT code": 2})

    def test_etw_symbols_select_the_captured_group_when_dll_names_match(self):
        provenance = {
            "runs": [{"label": label, "round": 0, "warmup": False}
                     for label in ("before", "after")],
            "metadata": {"vms": [
                {"label": label, "vm_type": "jit", "module": f"{label}/vm.dll"}
                for label in ("before", "after")]},
        }
        vm = etw_analysis.captured_vm(
            Path("round-0-before-native-samples.json"), {}, provenance)
        self.assertEqual(vm["module"], "before/vm.dll")

    def test_symbol_map_uses_only_code_labels_in_executable_sections(self):
        image = {"image_base": 0x180000000,
                 "sections": [{"rva": 0x1000, "size": 0x100}]}
        text = """ Preferred load address is 0000000180000000
 0001:00000000       lj_BC_TEST        0000000180001000 f   lj_vm.obj
 0001:00000000       lj_vm_asm_begin   0000000180001000     lj_vm.obj
 0001:00000080       private_helper    0000000180001080 f   ljamalg.c.obj
 0002:00000000       data_value        0000000180010000     ljamalg.c.obj
"""
        self.assertEqual(symbol_map.map_ranges(text, image), [
            (0x1000, 0x1080, "lj_BC_TEST"), (0x1080, 0x1100, "private_helper")])
        with self.assertRaisesRegex(ValueError, "image base"):
            symbol_map.map_ranges(text, dict(image, image_base=0))

    def test_etw_failed_export_is_not_reused_as_a_completed_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "cpu-samples.json"
            etl = root / "cpu.etl"
            etl.write_bytes(b"etl")
            metadata.write_text(json.dumps({"etl_path": str(etl), "pid": 42}))
            for suffix in (".csv", ".markers.json", ".stats.txt", ".images.csv"):
                etl.with_suffix(suffix).write_bytes(b"partial")
            with patch.object(etw_analysis, "tool_path", return_value="xperf"), \
                    patch.object(etw_analysis.subprocess, "run",
                                 return_value=SimpleNamespace(returncode=1)) as run:
                with self.assertRaisesRegex(RuntimeError, "statistics failed"):
                    etw_analysis.export_trace(metadata)
                self.assertEqual(run.call_count, 1)
            self.assertFalse(etl.with_suffix(".export.json").exists())

    def test_truncated_trace_summary_retains_only_complete_leading_fields(self):
        traces, diagnostics = analyze.trace_diagnostics([
            {"line": '[ds_perf] TRACE_SUMMARY attempt=1 '
             '{"trace_record_compile_wall_seconds":0.1,"events":{"flush":2},'
             '"abort_locations":{"long":"truncated'},
            {"line": '[ds_perf] TRACE_ROW attempt=1 {"trace":3,"size":12}'},
        ])
        self.assertTrue(diagnostics[0]["incomplete"])
        self.assertEqual(diagnostics[0]["events"]["flush"], 2)
        self.assertEqual(diagnostics[0]["trace_record_compile_wall_seconds"], 0.1)
        self.assertEqual(traces[0]["trace"], 3)

    def test_symbol_sidecar_rejects_a_different_measured_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "vm.dll"
            module.write_bytes(b"changed")
            sidecar = module.with_suffix(".symbols.json")
            sidecar.write_text(json.dumps({"module_sha256": "old"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match"):
                symbol_map.load_symbols(module, sidecar)

    def test_etw_jit_range_attribution_respects_flush_and_commit_times(self):
        capture = {"pid": 42, "thread_id": 7, "etl_path": "fixture.etl"}
        data = {
            "loss": {"events": 0, "buffers": 0}, "sampling_intervals": [],
            "markers": [{"kind": kind, "trace_us": at, "attempt": 1}
                        for kind, at in (("MAP_BEGIN", 0), ("MAP_END", 4000000))],
            "samples": [{"trace_us": at, "tid": 7, "address": 110,
                         "location": "Unknown!0x6e", "weight": 1, "stack": []}
                        for at in (500000, 1500000, 2500000)],
        }
        traces = [{"attempt": 1, "address": 100, "size": 20,
                   "elapsed_seconds": 1, "valid_until_seconds": 2}]
        summary = etw_analysis.summarize(capture, data, traces)["worldsim"]
        modules = {row["module"]: row["weight"] for row in summary["self_modules"]}
        self.assertEqual(modules["LuaJIT generated code"], 1)
        self.assertEqual(modules["<unresolved>"], 2)

    def test_etw_weights_target_cpu_events_and_keeps_stack_context(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cpu.csv"
            with path.open("w", encoding="utf-8", newline="") as stream:
                stream.write("OS Version: test, Events Lost: 0, Buffers lost: 0\n")
                writer = csv.writer(stream)
                writer.writerow(["SampledProfile", "TimeStamp", "Process Name ( PID)",
                                 "ThreadID", "PrgrmCtr", "CPU", "ThreadStartImage!Function",
                                 "Image!Function", "Count", "SampledProfile type"])
                writer.writerow(["Stack", "TimeStamp", "ThreadID", "No.",
                                 "Address", "Image!Function"])
                for kind, at in (("MAP_BEGIN", 10), ("MAP_END", 30)):
                    writer.writerow(["String", at, "DSPERF " + json.dumps({
                        "kind": kind, "pid": 42, "tid": 7, "attempt": 1})])
                writer.writerow(["SampledProfile", 9, "game.exe (42)", 7, "0x100",
                                 0, "", "game.exe!native", 50, "Unbatched"])
                writer.writerow(["SampledProfile", 12, "game.exe (42)", 7, "0x100",
                                 0, "", "game.exe!native", 3, "Batched"])
                writer.writerow(["Stack", 12, 7, 0, "0x100", "game.exe!native"])
                writer.writerow(["Stack", 12, 7, 1, "0x110", "game.exe!caller"])
                writer.writerow(["SampledProfile", 15, "game.exe (42)", 7, "0x200",
                                 0, "", "vm.dll!interpreter", 1, "Unbatched"])
                writer.writerow(["SampledProfile", 20, "other.exe (99)", 7, "0x100",
                                 0, "", "game.exe!native", 100, "Batched"])
            data = etw_analysis.parse_dump(path, 42)
            result = etw_analysis.summarize(
                {"pid": 42, "thread_id": 7, "etl_path": "fixture.etl"}, data)
        self.assertEqual(result["worldsim"]["sample_weight"], 4)
        self.assertEqual(result["worldsim"]["stack_coverage_percent"], 75)
        self.assertEqual(result["worldsim"]["self_modules"][0]["percent"], 75)
        self.assertEqual(result["worldsim"]["inclusive_modules"][0]["weight"], 3)
        self.assertEqual(result["worldsim"]["sample_events"], 2)

    def test_etw_rejects_lost_events_and_missing_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "loss.csv"
            path.write_text("Events Lost: 2, Buffers lost: 0\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "lost data"):
                etw_analysis.parse_dump(path, 42)
        with self.assertRaisesRegex(ValueError, "complete worldgen"):
            etw_analysis.summarize(
                {"pid": 42, "thread_id": 7, "etl_path": "fixture.etl"},
                {"markers": [], "samples": [], "loss": {},
                 "sampling_intervals": []})

    def test_hotspot_timeline_includes_retries_and_load_intervals_once(self):
        def row(at, line):
            return {"elapsed_seconds": at, "line": line}
        result = analyze.timelines([
            row(1, "[ds_perf] MAP_BEGIN attempt=1 seed=123 jit=false"),
            row(1.1, "[ds_perf] REQUIRE_BEGIN name=map/layouts"),
            row(1.3, "[ds_perf] REQUIRE_END name=map/layouts"),
            row(2, "[Ocean]  Square fill..."),
            row(4, "[Ocean]  Ground fill..."),
            row(5, "[ds_perf] MAP_END attempt=1 ok=false"),
            row(5.1, "[ds_perf] SAMPLE attempt=1 count=12 state=C stack=squareFill:154"),
            row(6, "[ds_perf] MAP_BEGIN attempt=2 seed=123 jit=false"),
            row(7, "[ds_perf] MAP_END attempt=2 ok=true"),
        ])
        self.assertEqual([attempt["wall_seconds"] for attempt in result], [4, 1])
        self.assertFalse(result[0]["success"])
        self.assertAlmostEqual(result[0]["require_wall_seconds"], 0.2)
        self.assertEqual(result[0]["phases"][1]["wall_seconds"], 2)
        self.assertEqual(result[0]["lua_samples"]["states"]["C"]["count"], 12)
        self.assertEqual(result[1]["lua_samples"]["total"], 0)
        with self.assertRaisesRegex(ValueError, "require end without begin"):
            analyze.timelines([
                row(1, "[ds_perf] MAP_BEGIN attempt=1"),
                row(2, "[ds_perf] REQUIRE_END name=map/layouts"),
            ])

    def test_native_samples_exclude_addresses_outside_map_intervals(self):
        attempts = [{"phases": [{"name": "square_fill", "begin_elapsed_seconds": 1,
                                "end_elapsed_seconds": 3}]}]
        capture = {
            "method": "fixture", "error": None, "suspension_call_seconds_total": 0.001,
            "suspension_call_seconds_max": 0.001,
            "modules": [{"path": "missing-fixture-vm.dll", "base": 100, "size": 100}],
            "samples": [{"elapsed_seconds": at, "rip": pc}
                        for at, pc in ((0, 101), (1, 110), (2, 999), (3, 120))],
        }
        result = analyze.native_summary(capture, attempts)
        self.assertEqual(result["samples_in_map"], 2)
        self.assertEqual(result["modules"][0]["percent"], 50)
        self.assertEqual(result["phase_modules"]["square_fill"]["missing-fixture-vm.dll"], 1)

    @unittest.skipUnless(perf.sys.platform == "win32", "Windows ETW")
    def test_etw_failure_does_not_fall_back_and_stops_only_owned_session(self):
        import native_sample
        with tempfile.TemporaryDirectory() as directory:
            sampler = native_sample.NativeSamples(Path(directory) / "native")
            with patch.object(sampler, "_control", side_effect=RuntimeError("denied")):
                with self.assertRaisesRegex(RuntimeError, "denied"):
                    sampler.start()
            self.assertFalse(sampler.started)
            sampler.started = True
            with patch.object(sampler, "_control") as control:
                sampler.finish()
                sampler.finish()
            control.assert_called_once_with("stop")
            self.assertTrue(sampler.session.startswith("DsPerf-"))
            self.assertEqual(sampler.result()["method"], "wpr_etw_cpu")

    def test_runtime_config_restores_original_bytes_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            game = Path(directory)
            path = game / "data/unsafedata/luajit_config.json"
            path.parent.mkdir(parents=True)
            original = b'{"modmain_path":"old/modmain.lua","AlwaysEnableMod":true}\r\n'
            path.write_bytes(original)
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                with perf.runtime_config(game, game / "release/Injector.dll"):
                    actual = json.loads(path.read_text())
                    self.assertFalse(actual["AlwaysEnableMod"])
                    self.assertEqual(actual["modmain_path"], str(game / "release/modmain.lua"))
                    path.write_text('{"modmain_path":"client rewrote the path"}', encoding="utf-8")
                    raise RuntimeError("fixture")
            self.assertEqual(path.read_bytes(), original)
            path.unlink()
            with perf.runtime_config(game, game / "release/Injector.dll"):
                self.assertTrue(path.is_file())
            self.assertFalse(path.exists())

    def test_runtime_confirmation_rejects_mixed_plugin_paths(self):
        injector = Path("release/Injector.dll").resolve()
        boot = f"[ds-bootstrap] loaded Injector: {injector}"
        perf.confirm_runtime([boot, f"[DynamicPluginLoader] loaded: {injector.parent}/plugins/core.dll"],
                             injector)
        with self.assertRaises(RuntimeError):
            perf.confirm_runtime([boot, "[DynamicPluginLoader] loaded: other/plugins/core.dll"],
                                 injector)

    @unittest.skipUnless(perf.sys.platform.startswith("win"), "Windows shell")
    def test_release_shell_restores_original_bytes_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            game = Path(directory)
            injector = game / "runtime/Injector.dll"
            source = injector.parent / "shell/Winmm.dll"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"release")
            path = game / "bin64/Winmm.dll"
            path.parent.mkdir()
            path.write_bytes(b"original debug")
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                with perf.release_shell(game, injector):
                    self.assertEqual(path.read_bytes(), b"release")
                    raise RuntimeError("fixture")
            self.assertEqual(path.read_bytes(), b"original debug")

    def test_release_build_rejects_assertions_and_debug_optimization(self):
        command = "cl /DWIN32 /DNDEBUG /O2 /Ob2 /MD /Fo luajit-5.1.dir/ljamalg.c.obj ljamalg.c"
        row = {"file": "ljamalg.c", "command": command}
        self.assertEqual(perf.build_release.validate_commands([row]), [command])
        for bad in (
            command + " /DLUA_USE_ASSERT", command + " /DLUA_USE_APICHECK",
            command + " /DLUAJIT_TEST_RETM", command + " /fsanitize=address",
            command + " /DLUAJIT_TEST_TAILCOUNT", command + " /DLUAJIT_PROFILE_TAILCOUNT",
            command + " /DLUAJIT_DIAG_OLDCACHE_TAILCOUNT",
            command.replace("/O2", "/Od"), command.replace("/MD", "/MDd"),
            command.replace("/DNDEBUG", ""), command.replace("/O2", "/O1"),
        ):
            with self.subTest(command=bad):
                with self.assertRaises(RuntimeError):
                    perf.build_release.validate_commands([{"file": "ljamalg.c", "command": bad}])

    def test_release_evidence_is_bound_to_binary_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "vm.dll"
            module.write_bytes(b"release")
            evidence = module.with_name(module.name + ".performance.json")
            with self.assertRaises(RuntimeError):
                perf.build_release.validate_release(module)
            evidence.write_text(json.dumps({
                "configuration": "Release", "sha256": perf.build_release.digest(module),
                "compile_commands": [{"file": "ljamalg.c", "command":
                    "cl /DNDEBUG /O2 /Fo luajit-5.1.dir/ljamalg.c.obj ljamalg.c"}],
            }), encoding="utf-8")
            perf.build_release.validate_release(module)
            module.write_bytes(b"assertion build")
            with self.assertRaises(RuntimeError):
                perf.build_release.validate_release(module)

    def test_game_vm_selector_uses_embedded_vm(self):
        self.assertEqual(perf.parse_vm("native=game"), ("native", None))

    def test_linux_cpu_parser_handles_spaces_and_parentheses_in_comm(self):
        import process_clock
        stat = "42 (game (server)) S " + " ".join(["0"] * 10 + ["100", "50"] + ["0"] * 30)
        self.assertEqual(process_clock.linux_cpu_seconds(stat, 100), 1.5)

    def test_module_confirmation_requires_a_successful_exact_load(self):
        module = Path("vm.dll").resolve()
        self.assertTrue(perf.module_confirmed([
            f"[core.vm] Attached Lua module (loadlib): {module}",
        ], module))
        self.assertTrue(perf.module_confirmed([
            f"[core.vm] Loaded Lua module: {module}",
        ], module))
        for lines in (
            [f"[core.vm] Cannot load Lua module: {module}, error: missing dependency"],
            [f"GAME_LUA_MODULE_NAME={module}"],
            [f"[core.vm] Attached Lua module (loadlib): {module}.other"],
        ):
            with self.subTest(lines=lines):
                self.assertFalse(perf.module_confirmed(lines, module))

    def test_worldgen_retries_are_included(self):
        observations = [
            (10.0, "[ds_perf] MAP_BEGIN attempt=1 seed=123 jit=false", 4.0),
            (12.0, "[ds_perf] MAP_END attempt=1 ok=false", 5.5),
            (13.0, "[ds_perf] MAP_BEGIN attempt=2 seed=123 jit=false", 6.0),
            (16.0, "[ds_perf] MAP_END attempt=2 ok=true", 8.5),
        ]
        result = perf.worldgen_metrics(observations, 123)
        self.assertEqual(result["worldgen_map_wall_seconds"], 5)
        self.assertEqual(result["worldgen_map_cpu_seconds"], 4)
        self.assertEqual(len(result["worldgen_attempts"]), 2)
        self.assertFalse(result["worldgen_jit_enabled"])

    def test_worldgen_requires_matching_seed_and_complete_success(self):
        for observations in (
            [(0, "[ds_perf] MAP_BEGIN attempt=1 seed=999 jit=false", 0)],
            [(0, "[ds_perf] MAP_BEGIN attempt=1 seed=123 jit=false", 0)],
            [(1, "[ds_perf] MAP_END attempt=1 ok=true", 1)],
            [(0, "[ds_perf] MAP_BEGIN attempt=1 seed=123 jit=false", 0),
             (1, "[ds_perf] MAP_END attempt=1 ok=false", 1)],
        ):
            with self.subTest(observations=observations):
                with self.assertRaises(RuntimeError):
                    perf.worldgen_metrics(observations, 123)

    def test_worldgen_jit_mode_is_verified_at_generation(self):
        observations = [
            (1, "[ds_perf] MAP_BEGIN attempt=1 seed=123 jit=true", 0),
            (3, "[ds_perf] MAP_END attempt=1 ok=true", 1),
        ]
        result = perf.worldgen_metrics(observations, 123, "on")
        self.assertTrue(result["worldgen_jit_enabled"])
        self.assertTrue(result["worldgen_attempts"][0]["jit_enabled"])
        with self.assertRaises(RuntimeError):
            perf.worldgen_metrics(observations, 123, "off")
        with self.assertRaises(RuntimeError):
            perf.worldgen_metrics([(1, "[ds_perf] MAP_BEGIN attempt=1 seed=123", 0),
                                   observations[1]], 123)

    def test_unavailable_cpu_clock_is_null_instead_of_wall_time(self):
        result = perf.worldgen_metrics([
            (1, "[ds_perf] MAP_BEGIN attempt=1 seed=123 jit=false", None),
            (3, "[ds_perf] MAP_END attempt=1 ok=true", None),
        ], 123)
        self.assertIsNone(result["worldgen_map_cpu_seconds"])

    def test_monotonic_first_observation_excludes_polling_delay(self):
        process = perf.smoke.LogProcess("fixture")
        process.started_at = 100
        with patch.object(perf.smoke.time, "perf_counter", side_effect=[102.5, 110]):
            process.observe("WORLD_READY")
            process.observe("WORLD_READY again")
        self.assertEqual(process.elapsed_until("WORLD_READY"), 2.5)
        self.assertIsNone(process.elapsed_until("missing"))

    def test_smoke_report_retains_failed_runs_and_excludes_hold_from_readiness(self):
        server = perf.smoke.LogProcess("server")
        server.started_at = 100
        client = perf.smoke.LogProcess("client")
        client.started_at = 120
        with patch.object(perf.smoke.time, "perf_counter", side_effect=[115, 125, 150]):
            server.observe("Telling Client our new session identifier")
            client.observe("LG_CLIENT_INJECT_OK")
            client.observe("LG_CLIENT_WORLD_READY")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "timings.json"
            with patch.object(perf.smoke.time, "perf_counter", return_value=180):
                with contextlib.redirect_stdout(io.StringIO()):
                    perf.smoke.report_timings("p1b", 99, 150, False, server, client, output)
            result = json.loads(output.read_text(encoding="utf-8"))
        self.assertFalse(result["success"])
        self.assertEqual(result["server_launch_to_world_seconds"], 15)
        self.assertEqual(result["client_launch_to_inject_seconds"], 5)
        self.assertEqual(result["client_launch_to_world_seconds"], 30)
        self.assertEqual(result["workflow_to_ready_seconds"], 51)
        self.assertEqual(result["test_total_seconds"], 81)

    def test_summary_pairs_rounds_and_excludes_warmup_and_failures(self):
        def row(label, round_number, value, warmup=False, success=True):
            return {"label": label, "round": round_number, "success": success,
                    "warmup": warmup, "worldgen_map_wall_seconds": value}
        result = perf.summarize([
            row("a", 0, 100, warmup=True), row("b", 0, 1, warmup=True),
            row("b", 1, 5), row("a", 1, 10),
            row("a", 2, 20), row("b", 2, 40),
            row("a", 3, 1000, success=False),
        ], ["a", "b"])
        self.assertEqual(result["groups"]["a"]["worldgen_map_wall_seconds"]["median"], 15)
        ratio = result["comparisons"]["b/a"]["worldgen_map_wall_seconds"]
        self.assertEqual(ratio["paired_samples"], 2)
        self.assertEqual(ratio["paired_ratios"], [0.5, 2])
        self.assertTrue(math.isclose(ratio["geometric_mean_ratio"], 1))


if __name__ == "__main__":
    unittest.main()
