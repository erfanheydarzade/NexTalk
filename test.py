import subprocess
import json
import sys
import copy
import base64
import random
import string

# ─────────────────────────────────────────────────────────────────────────────
# Core Runner (Exact User Implementation)
# ─────────────────────────────────────────────────────────────────────────────

def run_nextalk(command, args_list, payload=None, payload_flag=None):
    cmd = ["./nextalk.exe", "offline", command]
    cmd.extend(args_list)

    if payload is not None and payload_flag:
        cmd.extend([
            payload_flag,
            json.dumps(payload, separators=(",", ":"))
        ])

    result = subprocess.run(
        cmd,
        capture_output=True
    )
    

    stdout = result.stdout.decode(
        "utf-8",
        errors="replace",
    )

    stderr = result.stderr.decode(
        "utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        if not any(arg in sys.argv for arg in ["--silent-errors", "-s"]):
            print(f"\n[!] Command '{command}' failed.")
            print(stderr)
            print(stdout)
        return None

    try:
        start = stdout.find("{")
        end = stdout.rfind("}")

        if start == -1 or end == -1:
            if not any(arg in sys.argv for arg in ["--silent-errors", "-s"]):
                print(stdout)
            return None

        return json.loads(stdout[start:end + 1])

    except Exception as e:
        if not any(arg in sys.argv for arg in ["--silent-errors", "-s"]):
            print(f"\n[!] JSON Parse Error: {e}")
            print(stdout)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Test Framework Helpers
# ─────────────────────────────────────────────────────────────────────────────

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = {"passed": 0, "failed": 0}

def assert_payload(condition, label, details=""):
    if condition:
        results["passed"] += 1
        print(f"  {PASS} {label}")
    else:
        results["failed"] += 1
        suffix = f" — Got: {details}" if details else ""
        print(f"  {FAIL} {label}{suffix}")

def section(title):
    print(f"\n{'─'*50}\n  {title}\n{'─'*50}")

def extract_message(decrypted_json):
    try:
        return decrypted_json["data"]["message"]
    except (KeyError, TypeError):
        return None

def tamper_serialized_value(value):
    if not isinstance(value, str) or len(value) < 5:
        return value
    try:
        raw = base64.b64decode(value, validate=True)
        ba = bytearray(raw)
        idx = len(ba) // 2
        ba[idx] ^= 0xFF
        return base64.b64encode(bytes(ba)).decode("utf-8")
    except Exception:
        return value[::-1]

def truncate_serialized_value(value):
    if not isinstance(value, str) or len(value) < 10:
        return value
    return value[:-5]


# ─────────────────────────────────────────────────────────────────────────────
# Execution & Test Suites
# ─────────────────────────────────────────────────────────────────────────────

print("=======================================")
print("  NexTalk Ultimate Testing Engine v2.0 ")
print("=======================================")

# Initialize Baseline Peers
alice = run_nextalk("init", [])
bob = run_nextalk("init", [])
eve = run_nextalk("init", []) 

if not alice or not bob or not eve:
    sys.exit("[!] Critical initialization failure.")

print(f"[Init] Alice Peer ID: {alice['id'][:8]}")
print(f"[Init] Bob Peer ID:   {bob['id'][:8]}")
print(f"[Init] Eve Peer ID:   {eve['id'][:8]} (Attacker)")

# Establish Clean Session
offer = run_nextalk("offer", ["-i", alice["id"], "-r", bob["id"]])
answer = run_nextalk("accept", ["-i", bob["id"]], offer, "-o") if offer else None
finish = run_nextalk("finish", ["-i", alice["id"]], answer, "-a") if answer else None

if not finish:
    sys.exit("[!] Handshake sequence broken. Cannot proceed with tests.")


# ─── 1. HAPPY PATH (BASELINE) ────────────────────────────────────────────────
section("1 · Happy path (baseline)")

enc_happy = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", "hello"])
assert_payload(enc_happy is not None, "Alice encrypts 'hello'")

dec_happy = run_nextalk("decrypt", ["-i", bob["id"]], enc_happy, "-c") if enc_happy else None
assert_payload(extract_message(dec_happy) == "hello", "Bob decrypts → 'hello'")

enc_round = run_nextalk("encrypt", ["-i", bob["id"], "-r", alice["id"], "-m", "world"])
dec_round = run_nextalk("decrypt", ["-i", alice["id"]], enc_round, "-c") if enc_round else None
assert_payload(extract_message(dec_round) == "world", "Bob → Alice round-trip")


# ─── 2. DATA TYPE & BOUNDARY TESTS ───────────────────────────────────────────
section("2 · Data Type & Boundary Stress")

# 2.1 Empty String
enc_empty = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", ""])
dec_empty = run_nextalk("decrypt", ["-i", bob["id"]], enc_empty, "-c") if enc_empty else None
assert_payload(enc_empty is not None and extract_message(dec_empty) == "", "Empty string round-trip")

# 2.2 Whitespace only
ws_str = "   \n\t  \r  "
enc_ws = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", ws_str])
dec_ws = run_nextalk("decrypt", ["-i", bob["id"]], enc_ws, "-c") if enc_ws else None
assert_payload(extract_message(dec_ws) == ws_str, "Whitespace only round-trip")

# 2.3 5KB Large Payload (Windows CLI Safe Boundary)
huge_str = "X" * 5000
enc_huge = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", huge_str])
dec_huge = run_nextalk("decrypt", ["-i", bob["id"]], enc_huge, "-c") if enc_huge else None
assert_payload(dec_huge is not None and extract_message(dec_huge) == huge_str, "5 KB heavy message round-trip")

# 2.4 Unicode, Emojis, and RTL text
uni_str = "こんにちは 🔐 café naïve résumé 中文 ﷽"
enc_uni = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", uni_str])
dec_uni = run_nextalk("decrypt", ["-i", bob["id"]], enc_uni, "-c") if enc_uni else None
assert_payload(extract_message(dec_uni) == uni_str, "Complex Unicode / RTL / emoji round-trip")

# 2.5 JSON injection attempt in message
json_inj = '{"fake_field": "hacked", "data": null}'
enc_inj = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", json_inj])
dec_inj = run_nextalk("decrypt", ["-i", bob["id"]], enc_inj, "-c") if enc_inj else None
assert_payload(extract_message(dec_inj) == json_inj, "JSON string literal treated as pure text")


# ─── 3. CRYPTOGRAPHIC TAMPERING (CIPHERTEXT) ─────────────────────────────────
section("3 · Attack tests — ciphertext tampering")
sys.argv.append("--silent-errors")

base_msg = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", "secret"])

def diff_strings(a: str, b: str) -> str:
    max_len = max(len(a), len(b))
    result = []

    for i in range(max_len):
        ca = a[i] if i < len(a) else ""
        cb = b[i] if i < len(b) else ""

        if ca == cb:
            result.append("*")
        else:
            result.append(cb)

    return "".join(result)


# 3.1 Tamper ciphertext payload
tamp_payload = copy.deepcopy(base_msg)

print(tamp_payload, type(tamp_payload))

tamp_payload["data"]["c"] = tamper_serialized_value(
    tamp_payload["data"]["c"]
)

dec_tamp = run_nextalk(
    "decrypt",
    ["-i", bob["id"]],
    tamp_payload,
    "-c"
)

assert_payload(
    dec_tamp is None,
    f"Decryption rejects tampered ciphertext body "
    f"{diff_strings(
        base_msg["data"]["c"],
        tamp_payload["data"]["c"]
    )}"
)
# 3.2 Tamper MAC / Auth Tag (if separate) or Header
tamp_hdr = copy.deepcopy(base_msg)
if "data" in tamp_hdr and "t" in tamp_hdr["data"]:
    tamp_hdr["data"]["t"] = tamper_serialized_value(tamp_hdr["data"]["t"])
dec_hdr = run_nextalk("decrypt", ["-i", bob["id"]], tamp_hdr, "-c")
assert_payload(dec_hdr is None, "Decryption rejects tampered header/MAC")

# 3.3 Truncate Ciphertext
trunc_payload = copy.deepcopy(base_msg)
if "data" in trunc_payload and "c" in trunc_payload["data"]:
    trunc_payload["data"]["c"] = truncate_serialized_value(trunc_payload["data"]["c"])
dec_trunc = run_nextalk("decrypt", ["-i", bob["id"]], trunc_payload, "-c")
assert_payload(dec_trunc is None, "Decryption rejects truncated ciphertext body")

# 3.4 Change recipient ID in packet
hijack_recip = copy.deepcopy(base_msg)
if "data" in hijack_recip and "s" in hijack_recip["data"]:
    hijack_recip["data"]["s"] = eve["id"]
dec_hijack = run_nextalk("decrypt", ["-i", bob["id"]], hijack_recip, "-c")
assert_payload(dec_hijack is None, "Decryption rejects modified recipient ID in metadata")


# ─── 4. HANDSHAKE MANIPULATION & SPOOFING ────────────────────────────────────
section("4 · Attack tests — handshake manipulation")

# 4.1 Replay Offer
dup_offer = run_nextalk("accept", ["-i", bob["id"]], offer, "-o")
assert_payload(dup_offer is None, "Duplicate handshake offer processing blocked")

# 4.2 Replay Answer
dup_ans = run_nextalk("finish", ["-i", alice["id"]], answer, "-a")
assert_payload(dup_ans is None, "Duplicate handshake answer processing blocked")

# 4.3 Eve tries to accept Alice's offer to Bob
eve_accepts_alice = run_nextalk("accept", ["-i", eve["id"]], offer, "-o")
assert_payload(eve_accepts_alice is None, "Eve cannot accept an offer meant for Bob")

# 4.4 Modify Kyber/DH keys in offer
tamp_offer_keys = copy.deepcopy(offer)
for k in ["b", "d", "q"]:
    if k in tamp_offer_keys.get("data", {}):
        tamp_offer_keys["data"][k] = tamper_serialized_value(tamp_offer_keys["data"][k])
bad_ans_keys = run_nextalk("accept", ["-i", bob["id"]], tamp_offer_keys, "-o")
assert_payload(bad_ans_keys is None, "Handshake blocked when ECC/DH/Kyber keys tampered")

# 4.5 Break Handshake Signature
tamp_offer_sig = copy.deepcopy(offer)
if "v" in tamp_offer_sig.get("data", {}):
    tamp_offer_sig["data"]["v"] = tamper_serialized_value(tamp_offer_sig["data"]["v"])
bad_ans_sig = run_nextalk("accept", ["-i", bob["id"]], tamp_offer_sig, "-o")
assert_payload(bad_ans_sig is None, "Handshake blocked when Signature (v) is tampered")

# 4.6 Sender ID Hijacking
hijacked_offer = copy.deepcopy(offer)
if "i" in hijacked_offer.get("data", {}):
    hijacked_offer["data"]["i"] = eve["id"]
bad_id_ans = run_nextalk("accept", ["-i", bob["id"]], hijacked_offer, "-o")
assert_payload(bad_id_ans is None, "Handshake blocked when SenderID mismatches public key bind")


# ─── 5. TYPE CONFUSION ATTACKS ───────────────────────────────────────────────
section("5 · Type Confusion Attacks")

# 5.1 Pass Message payload to Accept
type_conf_accept = run_nextalk("accept", ["-i", bob["id"]], base_msg, "-o")
assert_payload(type_conf_accept is None, "Accept endpoint rejects 'message' type payload")

# 5.2 Pass Offer payload to Decrypt
type_conf_decrypt = run_nextalk("decrypt", ["-i", bob["id"]], offer, "-c")
assert_payload(type_conf_decrypt is None, "Decrypt endpoint rejects 'offer' type payload")

# 5.3 Pass Answer payload to Accept
type_conf_ans = run_nextalk("accept", ["-i", bob["id"]], answer, "-o")
assert_payload(type_conf_ans is None, "Accept endpoint rejects 'answer' type payload")



# ─── 6. MALFORMED JSON & GARBAGE ─────────────────────────────────────────────
section("6 · Malformed inputs & robustness")

garbage = {"random": "garbage", "array": [1,2,3]}
assert_payload(run_nextalk("decrypt", ["-i", bob["id"]], garbage, "-c") is None, "Decrypt ignores random JSON keys")
assert_payload(run_nextalk("accept", ["-i", bob["id"]], garbage, "-o") is None, "Accept ignores random JSON keys")

empty_json = {}
assert_payload(run_nextalk("finish", ["-i", alice["id"]], empty_json, "-a") is None, "Finish handles empty JSON {}")

no_data = {"type": "message"}
assert_payload(run_nextalk("decrypt", ["-i", bob["id"]], no_data, "-c") is None, "Graceful failure on missing 'data' object")


# ─── 7. SEQUENTIAL RATCHETING (CHAIN STRESS) ─────────────────────────────────
section("7 · Sequential Ratcheting Stress")
if "--silent-errors" in sys.argv: sys.argv.remove("--silent-errors")

seq_pass = True
enc_msgs = []
for i in range(20):
    msg = f"chain-msg-{i}"
    enc = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", msg])
    if not enc:
        seq_pass = False; break
    enc_msgs.append(enc)

if seq_pass:
    for i, enc in enumerate(enc_msgs):
        dec = run_nextalk("decrypt", ["-i", bob["id"]], enc, "-c")
        if dec is None or extract_message(dec) != f"chain-msg-{i}":
            seq_pass = False; break

assert_payload(seq_pass, "Ratchets survive 20 sequential unidirectional messages (A->B)")


# ─── 8. PING-PONG RATCHETING (DH STRESS) ─────────────────────────────────────
section("8 · Ping-Pong Ratcheting Stress")

pp_pass = True
for i in range(5):
    m_a = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", f"ping-{i}"])
    d_b = run_nextalk("decrypt", ["-i", bob["id"]], m_a, "-c") if m_a else None
    if not d_b or extract_message(d_b) != f"ping-{i}": pp_pass = False; break
    
    m_b = run_nextalk("encrypt", ["-i", bob["id"], "-r", alice["id"], "-m", f"pong-{i}"])
    d_a = run_nextalk("decrypt", ["-i", alice["id"]], m_b, "-c") if m_b else None
    if not d_a or extract_message(d_a) != f"pong-{i}": pp_pass = False; break

assert_payload(pp_pass, "Continuous Bidirectional Ping-Pong (10 turns) maintains DH key sync")


# ─── 9. MESSAGE REPLAY & DELETION ────────────────────────────────────────────
section("9 · Replay & Skip Attacks")
sys.argv.append("--silent-errors")

replay_dec = run_nextalk("decrypt", ["-i", bob["id"]], enc_msgs[0], "-c")
assert_payload(replay_dec is None, "Bob rejects replayed older message (Chain Msg 0)")

replay_ping = run_nextalk("decrypt", ["-i", bob["id"]], m_a, "-c")
assert_payload(replay_ping is None, "Bob rejects replayed Ping message")


# ─── 10. OUT-OF-ORDER (OOO) DELIVERY ─────────────────────────────────────────
section("10 · Out-of-Order delivery & key skipping")
if "--silent-errors" in sys.argv: sys.argv.remove("--silent-errors")

msg1 = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", "ooo-1"])
msg2 = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", "ooo-2"])
msg3 = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", "ooo-3"])

dec3 = run_nextalk("decrypt", ["-i", bob["id"]], msg3, "-c")
assert_payload(dec3 is not None and extract_message(dec3) == "ooo-3", "Bob decrypts future Msg 3 (skips 1 & 2)")

dec1 = run_nextalk("decrypt", ["-i", bob["id"]], msg1, "-c")
assert_payload(dec1 is not None and extract_message(dec1) == "ooo-1", "Bob recovers delayed Msg 1 from skipped keys")

dec2 = run_nextalk("decrypt", ["-i", bob["id"]], msg2, "-c")
assert_payload(dec2 is not None and extract_message(dec2) == "ooo-2", "Bob recovers delayed Msg 2 from skipped keys")


# ─── 11. EXTREME OUT-OF-ORDER (MAX SKIP) ─────────────────────────────────────
section("11 · Extreme Out-of-Order (Limit Testing)")

large_ooo_msgs = []
for i in range(30):
    large_ooo_msgs.append(run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", f"ext-{i}"]))

dec_last = run_nextalk("decrypt", ["-i", bob["id"]], large_ooo_msgs[-1], "-c")
assert_payload(dec_last is not None and extract_message(dec_last) == "ext-29", "Bob jumps ahead 30 messages successfully")

dec_mid = run_nextalk("decrypt", ["-i", bob["id"]], large_ooo_msgs[15], "-c")
assert_payload(dec_mid is not None and extract_message(dec_mid) == "ext-15", "Bob recovers Msg 15 from deep skip-key cache")

sys.argv.append("--silent-errors")
dec_mid_replay = run_nextalk("decrypt", ["-i", bob["id"]], large_ooo_msgs[15], "-c")
assert_payload(dec_mid_replay is None, "Skipped keys are deleted after use (Replay prevention)")


# ─── 12. MULTI-PEER ISOLATION ────────────────────────────────────────────────
section("12 · Session Isolation (Alice, Bob, Eve)")

enc_bob = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", "only-for-bob"])
eve_snoops = run_nextalk("decrypt", ["-i", eve["id"]], enc_bob, "-c")
assert_payload(eve_snoops is None, "Eve cannot decrypt message explicitly addressed to Bob")

offer_eve = run_nextalk("offer", ["-i", alice["id"], "-r", eve["id"]])
ans_eve = run_nextalk("accept", ["-i", eve["id"]], offer_eve, "-o")
fin_eve = run_nextalk("finish", ["-i", alice["id"]], ans_eve, "-a")

enc_eve = run_nextalk("encrypt", ["-i", alice["id"], "-r", eve["id"], "-m", "only-for-eve"])
bob_snoops = run_nextalk("decrypt", ["-i", bob["id"]], enc_eve, "-c")
assert_payload(bob_snoops is None, "Bob cannot decrypt message addressed to Eve")

dec_eve_legit = run_nextalk("decrypt", ["-i", eve["id"]], enc_eve, "-c")
assert_payload(extract_message(dec_eve_legit) == "only-for-eve", "Alice <-> Eve session works concurrently with Alice <-> Bob")


# ─── 13. ZERO-STATE & GHOST PEER ─────────────────────────────────────────────
section("13 · Zero-State Defenses")

ghost_enc = run_nextalk("encrypt", ["-i", bob["id"], "-r", eve["id"], "-m", "hello-ghost"])
assert_payload(ghost_enc is None, "Encryption blocked when no session exists (Bob->Eve)")

bad_fin_eve = run_nextalk("finish", ["-i", alice["id"]], {"type":"answer", "data": {"i": eve["id"]}}, "-a")
assert_payload(bad_fin_eve is None, "Finish handshake blocked for unsolicited answer")


# ─── 14. DOUBLE RATCHET DESYNC RECOVERY (HEALING) ────────────────────────────
section("14 · Desynchronization and Healing")
if "--silent-errors" in sys.argv: sys.argv.remove("--silent-errors")

m1 = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", "h1"])
m2 = run_nextalk("encrypt", ["-i", bob["id"], "-r", alice["id"], "-m", "h2"])

d2 = run_nextalk("decrypt", ["-i", alice["id"]], m2, "-c")
assert_payload(d2 is not None and extract_message(d2) == "h2", "Alice processes Bob's message despite dropping her own previous send")

m3 = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", "h3"])
d3 = run_nextalk("decrypt", ["-i", bob["id"]], m3, "-c")
assert_payload(d3 is not None and extract_message(d3) == "h3", "Protocol auto-heals after missed epoch update")


# ─── 15. CLI & ARGUMENT VALIDATION ───────────────────────────────────────────
section("15 · CLI Argument Robustness")
sys.argv.append("--silent-errors")

no_msg = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"]])
assert_payload(no_msg is None, "CLI rejects encrypt missing -m flag")

no_recip = run_nextalk("encrypt", ["-i", alice["id"], "-m", "test"])
assert_payload(no_recip is None, "CLI rejects encrypt missing -r flag")

bad_cmd = run_nextalk("hack_network", ["-i", alice["id"]])
assert_payload(bad_cmd is None, "CLI rejects unknown command action")


# ─── 16. STATE PERSISTENCE ───────────────────────────────────────────────────
section("16 · State Verification")

final_msg = run_nextalk("encrypt", ["-i", alice["id"], "-r", bob["id"], "-m", "final-test"])
final_dec = run_nextalk("decrypt", ["-i", bob["id"]], final_msg, "-c")
assert_payload(final_dec is not None and extract_message(final_dec) == "final-test", "State remains intact at the end of 60+ chaotic tests")


if "--silent-errors" in sys.argv: sys.argv.remove("--silent-errors")

# ─── SUMMARY ─────────────────────────────────────────────────────────────────
print(f"\n{'═'*40}")
print(f"   Execution Complete: {results['passed'] + results['failed']} Total Tests Executed")
print(f"   {PASS} Passed: {results['passed']}")
print(f"   {FAIL} Failed: {results['failed']}")
print(f"{'═'*40}")

if results["failed"] > 0:
    sys.exit(1)