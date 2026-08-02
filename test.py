#!/usr/bin/env python3
"""
test.py - Full functional test suite for NexTalk (offline mode)

Design goals (per requirements):
  * Every external process is launched with subprocess.run([...]) using an
    argument LIST - never shell=True, never a shell pipeline. Piping between
    commands (e.g. offer -> accept) is done in Python by capturing stdout
    from one call and feeding it as an argument to the next.
  * 10+ independent scenarios covering the full offline handshake + messaging
    protocol, error handling, replay protection and tamper detection.
  * A dedicated size-efficiency scenario measures the compiled binary size
    and the byte size of every envelope produced on the wire, since NexTalk
    is meant to work over tiny out-of-band channels (QR codes, copy/paste).
  * Everything runs 100% offline: no network calls are made anywhere in this
    script, and each scenario uses `nextalk offline ...` which never touches
    a transport backend (worker/proxy).

Place this file at the repo root (next to go.mod) and run it there, or pass
--repo to point at the checkout.

Usage:
    python3 test.py                    # build (if needed) + run all scenarios
    python3 test.py --no-build         # skip `go build`, use existing binary
    python3 test.py --bin ./nextalk    # point at an already-built binary
    python3 test.py --repo /path/repo  # repo root containing go.mod
    python3 test.py --keep             # keep the temp workdir for inspection
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_BIN_NAME = "nextalk.exe" if os.name == "nt" else "nextalk_test_bin"


# --------------------------------------------------------------------------- #
# Small test-framework scaffolding (no external deps -> works fully offline)
# --------------------------------------------------------------------------- #

class Scenario:
    def __init__(self, number, name):
        self.number = number
        self.name = name
        self.passed = None
        self.detail = ""
        self.elapsed = 0.0


class Runner:
    def __init__(self, binary, workdir):
        self.binary = str(binary)
        self.workdir = str(workdir)
        self.results = []

    def run_cli(self, args, cwd=None, stdin_bytes=None, timeout=15):
        """
        Invoke the compiled nextalk binary as: [binary, *args]

        This is a direct argument-list subprocess call - NOT a shell command,
        NOT shell=True, and NOT a pipeline string. Any "piping" of data
        between two nextalk invocations is done here in Python by passing
        the captured bytes from one call as stdin/argument to the next.
        """
        cmd = [self.binary] + args
        proc = subprocess.run(
            cmd,
            cwd=cwd or self.workdir,
            input=stdin_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,          # explicit: never invoke a shell
        )
        return proc

    def parse_json_line(self, stdout_bytes):
        """The CLI's --format json mode emits exactly one JSON line to stdout."""
        text = stdout_bytes.decode("utf-8", errors="replace").strip()
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)
        return json.loads(text)

    def record(self, scenario, passed, detail=""):
        scenario.passed = passed
        scenario.detail = detail
        self.results.append(scenario)
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] Scenario {scenario.number:02d} - {scenario.name}")
        if detail:
            for ln in str(detail).splitlines():
                print(f"        {ln}")

    def summary(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        print("\n" + "=" * 70)
        print(f"SUMMARY: {passed}/{total} scenarios passed, {failed} failed")
        print("=" * 70)
        for r in self.results:
            mark = "OK  " if r.passed else "FAIL"
            print(f"  [{mark}] #{r.number:02d} {r.name} ({r.elapsed:.3f}s)")
        return failed == 0


# --------------------------------------------------------------------------- #
# Build helpers
# --------------------------------------------------------------------------- #

def find_or_build_binary(repo_root, explicit_bin, do_build, build_dir):
    if explicit_bin:
        p = Path(explicit_bin).resolve()
        if not p.exists():
            print(f"ERROR: --bin path {p} does not exist")
            sys.exit(2)
        return p

    out_path = build_dir / DEFAULT_BIN_NAME

    if not do_build:
        for candidate in (repo_root / "nextalk", repo_root / "nextalk.exe", out_path):
            if candidate.exists():
                return candidate
        print("ERROR: no binary found and --no-build was passed.")
        sys.exit(2)

    go = shutil.which("go")
    if go is None:
        print("ERROR: `go` compiler not found on PATH. Install Go 1.21+ "
              "or pass --bin /path/to/prebuilt/nextalk")
        sys.exit(2)

    print(f"Building NexTalk with: go build -o {out_path} ./cmd/nextalk")
    proc = subprocess.run(
        [go, "build", "-o", str(out_path), "./cmd/nextalk"],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    if proc.returncode != 0:
        print("BUILD FAILED:")
        print(proc.stdout.decode(errors="replace"))
        print(proc.stderr.decode(errors="replace"))
        sys.exit(2)
    return out_path


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #

def scenario_01_init_identity(r):
    s = Scenario(1, "init: create peer identity (Alice) - JSON mode, offline")
    t0 = time.time()
    proc = r.run_cli(["offline", "init", "--format", "json"])
    s.elapsed = time.time() - t0
    ok = proc.returncode == 0
    detail = ""
    peer_id = None
    if ok:
        try:
            data = r.parse_json_line(proc.stdout)
            peer_id = data.get("id")
            ok = bool(peer_id)
            detail = f"peer_id={peer_id}"
        except Exception as e:
            ok = False
            detail = f"could not parse JSON output: {e}\nstdout={proc.stdout!r}"
    else:
        detail = f"exit={proc.returncode} stderr={proc.stderr.decode(errors='replace')}"
    r.record(s, ok, detail)
    return peer_id


def scenario_02_init_identity_bob(r):
    s = Scenario(2, "init: create peer identity (Bob) - independent identity file")
    t0 = time.time()
    proc = r.run_cli(["offline", "init", "--format", "json"])
    s.elapsed = time.time() - t0
    ok = proc.returncode == 0
    peer_id = None
    detail = ""
    if ok:
        try:
            data = r.parse_json_line(proc.stdout)
            peer_id = data.get("id")
            ok = bool(peer_id)
            detail = f"peer_id={peer_id}"
        except Exception as e:
            ok = False
            detail = str(e)
    r.record(s, ok, detail)
    return peer_id


def scenario_03_identity_files_persisted(r, alice_id, bob_id):
    s = Scenario(3, "init: identity JSON files persisted to disk (offline storage)")
    t0 = time.time()
    alice_file = Path(r.workdir) / f"{alice_id}.json"
    bob_file = Path(r.workdir) / f"{bob_id}.json"
    ok = alice_file.exists() and bob_file.exists()
    s.elapsed = time.time() - t0
    detail = (f"alice_file={alice_file.exists()} "
              f"({alice_file.stat().st_size if alice_file.exists() else 0}B), "
              f"bob_file={bob_file.exists()} "
              f"({bob_file.stat().st_size if bob_file.exists() else 0}B)")
    r.record(s, ok, detail)


def scenario_04_offer(r, alice_id, bob_id):
    s = Scenario(4, "offer: Alice generates a handshake offer for Bob")
    t0 = time.time()
    proc = r.run_cli(["offline", "offer", "-i", alice_id, "-r", bob_id, "--format", "json"])
    s.elapsed = time.time() - t0
    ok = proc.returncode == 0
    offer_env = None
    detail = ""
    if ok:
        try:
            data = r.parse_json_line(proc.stdout)
            offer_env = data.get("envelope")
            ok = bool(offer_env)
            parsed = json.loads(offer_env)
            ok = ok and parsed.get("type") == "offer"
            detail = f"envelope_type={parsed.get('type')}, bytes={len(offer_env)}"
        except Exception as e:
            ok = False
            detail = f"parse error: {e}\nstdout={proc.stdout!r}"
    else:
        detail = proc.stderr.decode(errors="replace")
    r.record(s, ok, detail)
    return offer_env


def scenario_05_accept(r, bob_id, offer_env):
    s = Scenario(5, "accept: Bob accepts Alice's offer, produces answer (Kyber encapsulation)")
    t0 = time.time()
    proc = r.run_cli(["offline", "accept", "-i", bob_id, "-e", offer_env, "--format", "json"])
    s.elapsed = time.time() - t0
    ok = proc.returncode == 0
    answer_env = None
    detail = ""
    if ok:
        try:
            data = r.parse_json_line(proc.stdout)
            answer_env = data.get("envelope")
            parsed = json.loads(answer_env)
            ok = parsed.get("type") == "answer"
            detail = f"envelope_type={parsed.get('type')}, bytes={len(answer_env)}"
        except Exception as e:
            ok = False
            detail = f"parse error: {e}\nstdout={proc.stdout!r}"
    else:
        detail = proc.stderr.decode(errors="replace")
    r.record(s, ok, detail)
    return answer_env


def scenario_06_finish(r, alice_id, answer_env):
    s = Scenario(6, "finish: Alice decapsulates Kyber ciphertext, session ratchet active")
    t0 = time.time()
    proc = r.run_cli(["offline", "finish", "-i", alice_id, "-a", answer_env, "--format", "json"])
    s.elapsed = time.time() - t0
    ok = proc.returncode == 0
    detail = proc.stdout.decode(errors="replace").strip() if ok else proc.stderr.decode(errors="replace")
    r.record(s, ok, detail)


def scenario_07_encrypt_decrypt_roundtrip(r, alice_id, bob_id):
    s = Scenario(7, "encrypt/decrypt: Alice -> Bob message round-trips correctly")
    t0 = time.time()
    plaintext = "hello Bob, this is an offline end-to-end test message"
    proc_enc = r.run_cli(["offline", "encrypt", "-i", alice_id, "-r", bob_id,
                           "-m", plaintext, "--format", "json"])
    ok = proc_enc.returncode == 0
    msg_env = None
    detail = ""
    if ok:
        try:
            data = r.parse_json_line(proc_enc.stdout)
            msg_env = data.get("envelope")
            ok = json.loads(msg_env).get("type") == "message"
        except Exception as e:
            s.elapsed = time.time() - t0
            r.record(s, False, f"encrypt parse error: {e}")
            return

    if ok:
        proc_dec = r.run_cli(["offline", "decrypt", "-i", bob_id, "-c", msg_env, "--format", "json"])
        ok = proc_dec.returncode == 0
        if ok:
            try:
                dec_data = r.parse_json_line(proc_dec.stdout)
                recovered = dec_data.get("message")
                ok = recovered == plaintext
                detail = f"sent={plaintext!r} recovered={recovered!r}"
            except Exception as e:
                ok = False
                detail = f"decrypt parse error: {e}\nstdout={proc_dec.stdout!r}"
        else:
            detail = proc_dec.stderr.decode(errors="replace")
    else:
        detail = proc_enc.stderr.decode(errors="replace")

    s.elapsed = time.time() - t0
    r.record(s, ok, detail)


def scenario_08_bidirectional_and_ordering(r, alice_id, bob_id):
    s = Scenario(8, "double ratchet: reply message (Bob -> Alice) + multi-message ordering")
    t0 = time.time()
    ok = True
    detail_lines = []
    try:
        reply_text = "hi Alice, got it!"
        proc = r.run_cli(["offline", "encrypt", "-i", bob_id, "-r", alice_id,
                           "-m", reply_text, "--format", "json"])
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        env = r.parse_json_line(proc.stdout)["envelope"]

        proc2 = r.run_cli(["offline", "decrypt", "-i", alice_id, "-c", env, "--format", "json"])
        assert proc2.returncode == 0, proc2.stderr.decode(errors="replace")
        recovered = r.parse_json_line(proc2.stdout)["message"]
        assert recovered == reply_text, f"expected {reply_text!r} got {recovered!r}"
        detail_lines.append(f"reply round-trip ok: {recovered!r}")

        second_text = "second message on the same session"
        proc3 = r.run_cli(["offline", "encrypt", "-i", alice_id, "-r", bob_id,
                            "-m", second_text, "--format", "json"])
        assert proc3.returncode == 0, proc3.stderr.decode(errors="replace")
        env2 = r.parse_json_line(proc3.stdout)["envelope"]
        n2 = json.loads(env2)["data"].get("n")

        proc4 = r.run_cli(["offline", "decrypt", "-i", bob_id, "-c", env2, "--format", "json"])
        assert proc4.returncode == 0, proc4.stderr.decode(errors="replace")
        recovered2 = r.parse_json_line(proc4.stdout)["message"]
        assert recovered2 == second_text
        detail_lines.append(f"second message counter n={n2}, recovered ok")
    except AssertionError as e:
        ok = False
        detail_lines.append(f"assertion failed: {e}")
    except Exception as e:
        ok = False
        detail_lines.append(f"unexpected error: {e}")

    s.elapsed = time.time() - t0
    r.record(s, ok, "\n".join(detail_lines))


def scenario_09_tamper_detection(r, alice_id, bob_id):
    s = Scenario(9, "security: tampered ciphertext/HMAC is rejected (integrity check)")
    t0 = time.time()
    ok = True
    detail = ""
    try:
        proc = r.run_cli(["offline", "encrypt", "-i", alice_id, "-r", bob_id,
                           "-m", "do not tamper with me", "--format", "json"])
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        env = r.parse_json_line(proc.stdout)["envelope"]
        parsed = json.loads(env)

        ct_field = parsed["data"].get("c", "")
        if not ct_field:
            raise AssertionError("no ciphertext field 'c' found in envelope to tamper with")
        tampered_char = "A" if ct_field[0] != "A" else "B"
        parsed["data"]["c"] = tampered_char + ct_field[1:]
        tampered_env = json.dumps(parsed)

        proc2 = r.run_cli(["offline", "decrypt", "-i", bob_id, "-c", tampered_env, "--format", "json"])
        ok = proc2.returncode != 0
        detail = (f"decrypt exit code on tampered input = {proc2.returncode} "
                  f"(non-zero expected) stderr={proc2.stderr.decode(errors='replace')[:200]}")
    except AssertionError as e:
        ok = False
        detail = f"assertion failed: {e}"
    except Exception as e:
        ok = False
        detail = f"unexpected error: {e}"

    s.elapsed = time.time() - t0
    r.record(s, ok, detail)


def scenario_10_replay_and_bad_input_handling(r, alice_id, bob_id):
    s = Scenario(10, "robustness: replayed message rejected + malformed/missing-arg errors handled")
    t0 = time.time()
    ok = True
    detail_lines = []
    try:
        proc = r.run_cli(["offline", "encrypt", "-i", alice_id, "-r", bob_id,
                           "-m", "replay-me-once", "--format", "json"])
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        env = r.parse_json_line(proc.stdout)["envelope"]

        proc2 = r.run_cli(["offline", "decrypt", "-i", bob_id, "-c", env, "--format", "json"])
        assert proc2.returncode == 0, proc2.stderr.decode(errors="replace")
        detail_lines.append("first delivery decrypted OK")

        proc3 = r.run_cli(["offline", "decrypt", "-i", bob_id, "-c", env, "--format", "json"])
        replay_rejected = proc3.returncode != 0
        detail_lines.append(f"replay attempt exit={proc3.returncode} "
                             f"({'rejected as expected' if replay_rejected else 'NOT REJECTED - BUG'})")
        ok = ok and replay_rejected

        proc4 = r.run_cli(["offline", "decrypt", "-i", bob_id, "-c", "{not-valid-json", "--format", "json"])
        malformed_rejected = proc4.returncode != 0
        detail_lines.append(f"malformed envelope exit={proc4.returncode} "
                             f"({'handled' if malformed_rejected else 'NOT HANDLED - BUG'})")
        ok = ok and malformed_rejected

        proc5 = r.run_cli(["offline", "encrypt", "-r", bob_id, "-m", "x", "--format", "json"])
        missing_flag_rejected = proc5.returncode != 0
        detail_lines.append(f"missing --id exit={proc5.returncode} "
                             f"({'handled' if missing_flag_rejected else 'NOT HANDLED - BUG'})")
        ok = ok and missing_flag_rejected

    except AssertionError as e:
        ok = False
        detail_lines.append(f"assertion failed: {e}")
    except Exception as e:
        ok = False
        detail_lines.append(f"unexpected error: {e}")

    s.elapsed = time.time() - t0
    r.record(s, ok, "\n".join(detail_lines))


def scenario_11_size_efficiency(r, binary_path, alice_id, bob_id):
    """
    NexTalk's offline mode is designed to move envelopes through very small
    out-of-band channels (QR codes, manual copy/paste, SMS), so both the
    compiled binary and the wire envelopes need to stay compact. This
    scenario measures both and applies generous, environment-agnostic
    thresholds so it stays meaningful across machines while still catching
    real regressions (e.g. an accidentally-embedded asset or ballooning
    envelope encoding).
    """
    s = Scenario(11, "size efficiency: binary size + envelope byte sizes (offline channels)")
    t0 = time.time()
    detail_lines = []
    ok = True
    try:
        bin_size = Path(binary_path).stat().st_size
        detail_lines.append(f"binary size: {bin_size:,} bytes ({bin_size/1_000_000:.2f} MB)")
        BIN_CEILING = 150 * 1024 * 1024
        if bin_size > BIN_CEILING:
            ok = False
            detail_lines.append(f"FAIL: binary exceeds {BIN_CEILING/1_000_000:.0f}MB ceiling")

        proc_offer = r.run_cli(["offline", "offer", "-i", alice_id, "-r", bob_id, "--format", "json"])
        offer_env = r.parse_json_line(proc_offer.stdout)["envelope"]
        offer_size = len(offer_env.encode("utf-8"))
        detail_lines.append(f"offer envelope: {offer_size} bytes")

        proc_accept = r.run_cli(["offline", "accept", "-i", bob_id, "-e", offer_env, "--format", "json"])
        answer_env = r.parse_json_line(proc_accept.stdout)["envelope"]
        answer_size = len(answer_env.encode("utf-8"))
        detail_lines.append(f"answer envelope: {answer_size} bytes")

        proc_finish = r.run_cli(["offline", "finish", "-i", alice_id, "-a", answer_env, "--format", "json"])
        assert proc_finish.returncode == 0

        proc_msg = r.run_cli(["offline", "encrypt", "-i", alice_id, "-r", bob_id,
                               "-m", "size test message", "--format", "json"])
        msg_env = r.parse_json_line(proc_msg.stdout)["envelope"]
        msg_size = len(msg_env.encode("utf-8"))
        detail_lines.append(f"message envelope (19-char plaintext): {msg_size} bytes")

        # Handshake envelopes carry Kyber768 + Dilithium3 keys/sigs, so a few
        # KB is expected for hybrid PQ crypto. Only flag gross regressions.
        HANDSHAKE_CEILING = 20_000   # bytes
        MESSAGE_CEILING = 2_000      # bytes, for a short plaintext message

        if offer_size > HANDSHAKE_CEILING:
            ok = False
            detail_lines.append(f"FAIL: offer envelope unexpectedly large (> {HANDSHAKE_CEILING}B)")
        if answer_size > HANDSHAKE_CEILING:
            ok = False
            detail_lines.append(f"FAIL: answer envelope unexpectedly large (> {HANDSHAKE_CEILING}B)")
        if msg_size > MESSAGE_CEILING:
            ok = False
            detail_lines.append(f"FAIL: message envelope unexpectedly large (> {MESSAGE_CEILING}B) "
                                 f"for a short plaintext - bad for QR/offline transport")

        detail_lines.append(
            "note: these are copy/paste-over-offline-channel payloads; "
            "smaller is strictly better for QR-code and SMS-based exchange."
        )
    except AssertionError as e:
        ok = False
        detail_lines.append(f"assertion failed: {e}")
    except Exception as e:
        ok = False
        detail_lines.append(f"unexpected error: {e}")

    s.elapsed = time.time() - t0
    r.record(s, ok, "\n".join(detail_lines))


def scenario_12_contacts_offline(r, bob_id):
    s = Scenario(12, "contacts: add/list/remove alias works fully offline (local JSON store)")
    t0 = time.time()
    ok = True
    detail_lines = []
    try:
        proc_add = r.run_cli(["contacts", "add", "bob-alias", bob_id])
        assert proc_add.returncode == 0, proc_add.stderr.decode(errors="replace")
        detail_lines.append("contacts add: ok")

        proc_list = r.run_cli(["contacts", "list"])
        assert proc_list.returncode == 0, proc_list.stderr.decode(errors="replace")
        listed = proc_list.stdout.decode(errors="replace")
        assert "bob-alias" in listed, f"alias not found in list output: {listed!r}"
        detail_lines.append("contacts list: alias present")

        proc_remove = r.run_cli(["contacts", "remove", "bob-alias"])
        ok = proc_remove.returncode == 0
        detail_lines.append(f"contacts remove exit={proc_remove.returncode}")
    except AssertionError as e:
        ok = False
        detail_lines.append(f"assertion failed: {e}")
    except Exception as e:
        ok = False
        detail_lines.append(f"unexpected error: {e}")

    s.elapsed = time.time() - t0
    r.record(s, ok, "\n".join(detail_lines))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="NexTalk offline CLI test suite")
    parser.add_argument("--repo", default=".", help="repo root containing go.mod (default: cwd)")
    parser.add_argument("--bin", help="path to a prebuilt nextalk binary")
    parser.add_argument("--no-build", action="store_true", help="do not run `go build`")
    parser.add_argument("--keep", action="store_true", help="keep the temp workdir afterwards")
    args = parser.parse_args()

    repo_root = Path(args.repo).resolve()
    build_dir = repo_root / ".testbuild"
    build_dir.mkdir(exist_ok=True)

    binary_path = find_or_build_binary(repo_root, args.bin, not args.no_build, build_dir)
    print(f"Using binary: {binary_path}\n")

    workdir = Path(tempfile.mkdtemp(prefix="nextalk_offline_test_"))
    print(f"Isolated offline workdir: {workdir}\n")

    r = Runner(binary_path, workdir)

    try:
        alice_id = scenario_01_init_identity(r)
        bob_id = scenario_02_init_identity_bob(r)

        if not (alice_id and bob_id):
            print("\nAborting remaining scenarios: identity creation failed.")
            r.summary()
            sys.exit(1)

        scenario_03_identity_files_persisted(r, alice_id, bob_id)

        offer_env = scenario_04_offer(r, alice_id, bob_id)
        if not offer_env:
            print("\nAborting remaining scenarios: offer generation failed.")
            r.summary()
            sys.exit(1)

        answer_env = scenario_05_accept(r, bob_id, offer_env)
        if not answer_env:
            print("\nAborting remaining scenarios: accept step failed.")
            r.summary()
            sys.exit(1)

        scenario_06_finish(r, alice_id, answer_env)
        scenario_07_encrypt_decrypt_roundtrip(r, alice_id, bob_id)
        scenario_08_bidirectional_and_ordering(r, alice_id, bob_id)
        scenario_09_tamper_detection(r, alice_id, bob_id)
        scenario_10_replay_and_bad_input_handling(r, alice_id, bob_id)
        scenario_11_size_efficiency(r, binary_path, alice_id, bob_id)
        scenario_12_contacts_offline(r, bob_id)

        all_ok = r.summary()
    finally:
        if args.keep:
            print(f"\n(--keep) workdir left at: {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()