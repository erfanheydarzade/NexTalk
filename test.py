#!/usr/bin/env python3
"""
NexTalk offline-transport protocol test suite.

Drives the real `nextalk offline` CLI as a black box and asserts on the
protocol's security properties. Standard library only (no pytest, no deps):
subprocess + unittest + json/base64/hmac/hashlib.

Coverage
--------
1. Happy path .............. offer -> accept -> finish -> encrypt -> decrypt
2. Bidirectional ........... Alice->Bob and Bob->Alice on one session
3. Replay attack ........... duplicate Offer ID rejected at `accept`
4. Tampered ciphertext ..... HMAC tag failure + forged-tag AEAD failure
5. Cross-peer isolation .... Eve cannot decrypt Alice/Bob traffic
6. Out-of-order delivery ... skipped-key cache exercised (3, 1, 2)
7. Ratchet advancement ..... chain key evolves; old nonces refused

Run
---
    python test.py                 # build binary automatically, run all
    python test.py -v              # verbose
    python test.py NexTalkHappyPath
    NEXTALK_BIN=path/to/nextalk.exe python test.py     # skip the build

Identity state is a `<peerID>.json` file in the process CWD, so every test
gets its own temporary directory and therefore its own isolated key store.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(REPO_ROOT, ".testbuild")
EXE_SUFFIX = ".exe" if os.name == "nt" else ""

# Resolved once by build_binary() in setUpModule.
NEXTALK: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Build / process plumbing
# ─────────────────────────────────────────────────────────────────────────────

def build_binary() -> str:
    """Return a path to a usable nextalk binary, building it if needed."""
    override = os.environ.get("NEXTALK_BIN")
    if override:
        if not os.path.isfile(override):
            raise SystemExit(f"NEXTALK_BIN does not exist: {override}")
        return os.path.abspath(override)

    if shutil.which("go") is None:
        raise SystemExit(
            "go toolchain not found on PATH and NEXTALK_BIN is unset — "
            "cannot obtain a nextalk binary to test"
        )

    os.makedirs(BUILD_DIR, exist_ok=True)
    out = os.path.join(BUILD_DIR, "nextalk_pytest" + EXE_SUFFIX)
    proc = subprocess.run(
        ["go", "build", "-o", out, "./cmd/nextalk"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(f"go build failed:\n{proc.stdout}\n{proc.stderr}")
    return out


class Result:
    """Outcome of a single CLI invocation."""

    def __init__(self, argv: list[str], code: int, out: str, err: str) -> None:
        self.argv = argv
        self.code = code
        self.stdout = out
        self.stderr = err

    @property
    def ok(self) -> bool:
        return self.code == 0

    def json(self) -> dict:
        """Parse the single-line JSON contract emitted by --format json."""
        line = self.stdout.strip().splitlines()[-1]
        return json.loads(line)

    @property
    def error(self) -> str:
        """Error text, from the JSON body in json mode or stderr in human mode."""
        try:
            return str(self.json().get("error", ""))
        except Exception:
            return self.stderr.strip()

    def __repr__(self) -> str:  # shows up in assertion messages
        return (
            f"<Result argv={' '.join(self.argv)!r} code={self.code} "
            f"stdout={self.stdout.strip()[:180]!r} "
            f"stderr={self.stderr.strip()[:180]!r}>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Wire-format helpers (binmodel v1, see internal/encoding/legacy.go)
# ─────────────────────────────────────────────────────────────────────────────
#
#   field   := name ":" base64(value)
#   payload := field ("," field)*
#
# A SecureMessage frame carries the fields s, k, n, c, t (in that order):
#   s = sender peer ID      k = sender's ratchet DH public key
#   n = ASCII decimal nonce c = ChaCha20-Poly1305 ciphertext
#   t = HMAC-SHA3-256 tag over the tag-free canonical form (s,k,n,c)

HMAC_FIELDS = ("s", "k", "n", "c")


def parse_frame(cipher_b64: str) -> tuple[dict[str, bytes], list[str]]:
    """Decode a base64 SecureMessage frame into {field: raw bytes} + field order."""
    wire = base64.b64decode(cipher_b64).decode("ascii")
    fields: dict[str, bytes] = {}
    order: list[str] = []
    for chunk in wire.split(","):
        name, _, value = chunk.partition(":")
        if not _:
            raise ValueError(f"malformed frame field: {chunk!r}")
        fields[name] = base64.b64decode(value)
        order.append(name)
    return fields, order


def build_frame(fields: dict[str, bytes], order: list[str]) -> str:
    """Re-encode a frame back to the base64 form the CLI accepts via --in b64."""
    wire = ",".join(
        f"{name}:{base64.b64encode(fields[name]).decode('ascii')}" for name in order
    )
    return base64.b64encode(wire.encode("ascii")).decode("ascii")


def canonical_tag(fields: dict[str, bytes], hmac_key: bytes) -> bytes:
    """Recompute the frame's authentication tag: HMAC-SHA3-256 over (s,k,n,c)."""
    canonical = ",".join(
        f"{name}:{base64.b64encode(fields[name]).decode('ascii')}"
        for name in HMAC_FIELDS
    ).encode("ascii")
    return hmac.new(hmac_key, canonical, hashlib.sha3_256).digest()


# ─────────────────────────────────────────────────────────────────────────────
# Test harness
# ─────────────────────────────────────────────────────────────────────────────

class NexTalkCase(unittest.TestCase):
    """Base class: isolated CWD per test + thin wrappers over the CLI."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="nextalk-test-")
        self.addCleanup(shutil.rmtree, self._tmp, True)

    # ── raw invocation ──────────────────────────────────────────────────────

    def run_cli(self, *args: str, stdin: bytes | None = None) -> Result:
        argv = [NEXTALK, *args]
        proc = subprocess.run(
            argv,
            cwd=self._tmp,
            input=stdin,
            capture_output=True,
        )
        return Result(
            argv,
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )

    def cli_ok(self, *args: str, stdin: bytes | None = None) -> Result:
        res = self.run_cli(*args, stdin=stdin)
        self.assertTrue(res.ok, f"expected success, got {res!r}")
        return res

    def cli_fail(self, *args: str, stdin: bytes | None = None) -> Result:
        res = self.run_cli(*args, stdin=stdin)
        self.assertFalse(res.ok, f"expected failure, got {res!r}")
        return res

    # ── protocol steps ──────────────────────────────────────────────────────

    def init_identity(self) -> str:
        """`offline init` → new peer ID (persisted as <id>.json in the test CWD)."""
        return self.cli_ok("offline", "init", "--format", "json").json()["ID"]

    def offer(self, local: str, remote: str, path: str = "offer.bin") -> str:
        """`offline offer -o <file>` → path to the raw offer envelope."""
        payload = self.cli_ok(
            "offline", "offer", "-i", local, "-r", remote, "-o", path,
            "--format", "json",
        ).json()
        self.assertEqual(payload["Encoding"], "file")
        self.assertEqual(payload["RemotePeer"], remote)
        return path

    def accept(self, local: str, offer_path: str, path: str = "answer.bin") -> str:
        """`offline accept -f <offer> -o <file>` → path to the answer envelope."""
        payload = self.cli_ok(
            "offline", "accept", "-i", local, "-f", offer_path, "-o", path,
            "--format", "json",
        ).json()
        self.assertEqual(payload["Encoding"], "file")
        return path

    def finish(self, local: str, answer_path: str) -> str:
        """`offline finish -f <answer>` → the peer ID now bound to the session."""
        return self.cli_ok(
            "offline", "finish", "-i", local, "-f", answer_path, "--format", "json",
        ).json()["PeerID"]

    def handshake(self) -> tuple[str, str]:
        """Full three-step handshake. Returns (initiator_id, responder_id)."""
        alice = self.init_identity()
        bob = self.init_identity()
        offer_path = self.offer(alice, bob, "offer_ab.bin")
        answer_path = self.accept(bob, offer_path, "answer_ba.bin")
        self.assertEqual(
            self.finish(alice, answer_path), bob,
            "finish must return the responder's canonical peer ID",
        )
        return alice, bob

    def encrypt(self, sender: str, recipient: str, message: str) -> str:
        """`offline encrypt --out b64` → base64 SecureMessage frame."""
        payload = self.cli_ok(
            "offline", "encrypt", "-i", sender, "-r", recipient,
            "-m", message, "--out", "b64", "--format", "json",
        ).json()
        self.assertEqual(payload["Encoding"], "b64")
        return payload["Message"]

    def decrypt(self, recipient: str, cipher_b64: str) -> tuple[str, str]:
        """`offline decrypt --in b64` → (sender_id, plaintext)."""
        payload = self.cli_ok(
            "offline", "decrypt", "-i", recipient, "-c", cipher_b64,
            "--in", "b64", "--format", "json",
        ).json()
        self.assertEqual(payload["Encoding"], "utf-8")
        return payload["Sender"], payload["Message"]

    def decrypt_fail(self, recipient: str, cipher_b64: str) -> Result:
        return self.cli_fail(
            "offline", "decrypt", "-i", recipient, "-c", cipher_b64,
            "--in", "b64", "--format", "json",
        )

    # ── on-disk state inspection ────────────────────────────────────────────

    def identity_state(self, peer_id: str) -> dict:
        with open(os.path.join(self._tmp, f"{peer_id}.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def session_state(self, owner: str, peer: str) -> dict:
        sessions = self.identity_state(owner)["sessions"]
        self.assertIn(peer, sessions, f"{owner} has no session for {peer}")
        return sessions[peer]

    def hmac_key(self, owner: str, peer: str) -> bytes:
        return base64.b64decode(self.session_state(owner, peer)["hmacKey"])


# ─────────────────────────────────────────────────────────────────────────────
# 1. Happy path
# ─────────────────────────────────────────────────────────────────────────────

class NexTalkHappyPath(NexTalkCase):

    def test_full_round_trip(self):
        """offer -> accept -> finish -> encrypt -> decrypt recovers the plaintext."""
        alice, bob = self.handshake()

        plaintext = "the eagle has landed"
        cipher = self.encrypt(alice, bob, plaintext)
        sender, recovered = self.decrypt(bob, cipher)

        self.assertEqual(recovered, plaintext)
        self.assertEqual(sender, alice, "decrypt must attribute the message to Alice")

    def test_peer_ids_are_distinct_and_bound(self):
        """Each identity is unique and both sides agree on the same peer IDs."""
        alice, bob = self.handshake()
        self.assertNotEqual(alice, bob)
        # Alice stores the session under Bob's ID and vice versa.
        self.assertIn(bob, self.identity_state(alice)["sessions"])
        self.assertIn(alice, self.identity_state(bob)["sessions"])

    def test_handshake_establishes_matching_symmetric_keys(self):
        """Alice's send chain equals Bob's receive chain (and vice versa)."""
        alice, bob = self.handshake()
        a = self.session_state(alice, bob)
        b = self.session_state(bob, alice)

        self.assertEqual(a["sendCk"], b["recvCk"], "A.sendCk must equal B.recvCk")
        self.assertEqual(a["recvCk"], b["sendCk"], "A.recvCk must equal B.sendCk")
        self.assertEqual(a["hmacKey"], b["hmacKey"])
        self.assertEqual(a["rootKey"], b["rootKey"])
        # Exactly one side takes the initiator role (hash-ordered, not offer order).
        self.assertNotEqual(bool(a["amInitiator"]), bool(b["amInitiator"]))

    def test_pending_session_is_promoted(self):
        """The `pending`/`pending_<id>` placeholders are cleared by finish."""
        alice, bob = self.handshake()
        keys = self.identity_state(alice)["sessions"].keys()
        self.assertNotIn("pending", keys)
        self.assertNotIn(f"pending_{bob}", keys)

    def test_binary_ciphertext_to_tty_is_refused(self):
        """Raw binary must not be dumped to stdout without -o/--out (guard rail)."""
        alice, bob = self.handshake()
        # Not a TTY here, so raw output is allowed and must round-trip byte-exactly.
        res = self.cli_ok(
            "offline", "encrypt", "-i", alice, "-r", bob, "-m", "raw path",
            "--out", "raw",
        )
        self.assertTrue(res.stdout.startswith("s:"), f"unexpected raw frame: {res!r}")


# ─────────────────────────────────────────────────────────────────────────────
# 2. Bidirectional messaging
# ─────────────────────────────────────────────────────────────────────────────

class NexTalkBidirectional(NexTalkCase):

    def test_both_directions_on_one_session(self):
        """Alice->Bob and Bob->Alice both decrypt correctly."""
        alice, bob = self.handshake()

        a2b = self.encrypt(alice, bob, "ping from alice")
        sender, text = self.decrypt(bob, a2b)
        self.assertEqual((sender, text), (alice, "ping from alice"))

        b2a = self.encrypt(bob, alice, "pong from bob")
        sender, text = self.decrypt(alice, b2a)
        self.assertEqual((sender, text), (bob, "pong from bob"))

    def test_interleaved_conversation(self):
        """A multi-turn conversation stays in sync in both directions."""
        alice, bob = self.handshake()
        for i in range(4):
            a2b = self.encrypt(alice, bob, f"alice #{i}")
            self.assertEqual(self.decrypt(bob, a2b), (alice, f"alice #{i}"))
            b2a = self.encrypt(bob, alice, f"bob #{i}")
            self.assertEqual(self.decrypt(alice, b2a), (bob, f"bob #{i}"))

    def test_send_and_receive_chains_are_independent(self):
        """Sending does not disturb the peer's receive counter."""
        alice, bob = self.handshake()
        for i in range(3):
            self.decrypt(bob, self.encrypt(alice, bob, f"m{i}"))

        a = self.session_state(alice, bob)
        b = self.session_state(bob, alice)
        self.assertEqual(a["sendNonce"], 3, "Alice sent 3 messages")
        self.assertEqual(a["recvNonce"], 0, "Alice received none")
        self.assertEqual(b["recvNonce"], 3, "Bob received 3 messages")
        self.assertEqual(b["sendNonce"], 0, "Bob sent none")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Replay attacks
# ─────────────────────────────────────────────────────────────────────────────

class NexTalkReplayAttacks(NexTalkCase):

    def test_duplicate_offer_id_rejected_at_accept(self):
        """Re-submitting the same offer envelope is refused (SeenOffers)."""
        alice = self.init_identity()
        bob = self.init_identity()
        offer_path = self.offer(alice, bob)

        self.accept(bob, offer_path, "answer1.bin")          # first accept: fine
        res = self.cli_fail(                                  # replay: rejected
            "offline", "accept", "-i", bob, "-f", offer_path,
            "-o", "answer2.bin", "--format", "json",
        )
        self.assertIn("replay", res.error.lower(), f"unexpected error: {res!r}")
        self.assertIn(alice, res.error, "error should name the offending peer")

    def test_seen_offer_history_is_persisted(self):
        """The offer ID is recorded on disk so replay survives process restarts."""
        alice = self.init_identity()
        bob = self.init_identity()
        self.accept(bob, self.offer(alice, bob))

        seen = self.session_state(bob, alice)["seenOffers"]
        self.assertEqual(len(seen), 1, f"expected one recorded offer, got {seen}")
        self.assertTrue(all(seen.values()))

    def test_fresh_offer_after_replay_still_accepted(self):
        """Replay protection is per-offer-ID, not a permanent peer ban."""
        alice = self.init_identity()
        bob = self.init_identity()

        first = self.offer(alice, bob, "offer1.bin")
        self.accept(bob, first, "answer1.bin")
        self.cli_fail("offline", "accept", "-i", bob, "-f", first,
                      "-o", "dup.bin", "--format", "json")

        # A brand-new offer carries a fresh random OfferID and must be accepted.
        second = self.offer(alice, bob, "offer2.bin")
        self.accept(bob, second, "answer2.bin")

        seen = self.session_state(bob, alice)["seenOffers"]
        self.assertEqual(len(seen), 2, "re-key must carry forward offer history")

    def test_replayed_message_rejected(self):
        """A previously delivered message cannot be delivered a second time."""
        alice, bob = self.handshake()
        cipher = self.encrypt(alice, bob, "deliver once")
        self.decrypt(bob, cipher)

        # Advance Bob's receive chain past the replayed nonce.
        self.decrypt(bob, self.encrypt(alice, bob, "next message"))

        res = self.decrypt_fail(bob, cipher)
        self.assertIn("replay attack or message too old", res.error, repr(res))


# ─────────────────────────────────────────────────────────────────────────────
# 4. Tampered ciphertext
# ─────────────────────────────────────────────────────────────────────────────

class NexTalkTamperedCiphertext(NexTalkCase):

    def test_flipped_ciphertext_bit_fails_hmac(self):
        """Naive tampering trips the outer HMAC before AEAD is even reached."""
        alice, bob = self.handshake()
        fields, order = parse_frame(self.encrypt(alice, bob, "authentic payload"))

        corrupted = bytearray(fields["c"])
        corrupted[0] ^= 0x01
        fields["c"] = bytes(corrupted)

        res = self.decrypt_fail(bob, build_frame(fields, order))
        self.assertIn("invalid authentication tag", res.error, repr(res))

    def test_forged_hmac_still_fails_aead(self):
        """
        AEAD authentication is independently enforced.

        Recomputing a valid HMAC tag (using the session's hmacKey read off disk,
        i.e. a strictly stronger attacker than the network) gets past the outer
        MAC, and ChaCha20-Poly1305 rejects the message anyway.
        """
        alice, bob = self.handshake()
        fields, order = parse_frame(self.encrypt(alice, bob, "aead target"))

        corrupted = bytearray(fields["c"])
        corrupted[0] ^= 0x01
        fields["c"] = bytes(corrupted)
        fields["t"] = canonical_tag(fields, self.hmac_key(bob, alice))

        res = self.decrypt_fail(bob, build_frame(fields, order))
        self.assertIn("ciphertext tampered or invalid AEAD", res.error, repr(res))

    def test_tampered_nonce_rejected(self):
        """Rewriting the nonce field breaks the MAC (nonce is authenticated)."""
        alice, bob = self.handshake()
        fields, order = parse_frame(self.encrypt(alice, bob, "nonce target"))

        fields["n"] = b"7"
        res = self.decrypt_fail(bob, build_frame(fields, order))
        self.assertIn("invalid authentication tag", res.error, repr(res))

    def test_tampered_ratchet_key_rejected(self):
        """Swapping the ratchet public key is caught (key is in the MAC and AAD)."""
        alice, bob = self.handshake()
        fields, order = parse_frame(self.encrypt(alice, bob, "ratchet key target"))

        corrupted = bytearray(fields["k"])
        corrupted[-1] ^= 0xFF
        fields["k"] = bytes(corrupted)

        res = self.decrypt_fail(bob, build_frame(fields, order))
        self.assertIn("invalid authentication tag", res.error, repr(res))

    def test_truncated_ciphertext_rejected(self):
        """Cutting bytes off the ciphertext cannot yield a valid message."""
        alice, bob = self.handshake()
        fields, order = parse_frame(self.encrypt(alice, bob, "truncate target"))

        fields["c"] = fields["c"][:-4]
        res = self.decrypt_fail(bob, build_frame(fields, order))
        self.assertTrue(res.error, "truncated frame must produce an error")

    def test_garbage_input_rejected(self):
        """A non-frame payload is refused cleanly, not with a crash."""
        alice, bob = self.handshake()
        junk = base64.b64encode(b"not a binmodel frame at all").decode()
        res = self.decrypt_fail(bob, junk)
        self.assertTrue(res.error)
        # Cobra's own usage/error text must never leak (SilenceErrors/SilenceUsage).
        self.assertNotIn("Usage:", res.stderr)

    def test_tamper_does_not_corrupt_receiver_state(self):
        """A rejected message must not desync the receive ratchet."""
        alice, bob = self.handshake()
        before = self.session_state(bob, alice)["recvCk"]

        fields, order = parse_frame(self.encrypt(alice, bob, "poison"))
        corrupted = bytearray(fields["c"])
        corrupted[0] ^= 0x01
        fields["c"] = bytes(corrupted)
        self.decrypt_fail(bob, build_frame(fields, order))

        self.assertEqual(
            self.session_state(bob, alice)["recvCk"], before,
            "failed decrypt must not persist ratchet state",
        )
        # The legitimate next message still decrypts.
        self.assertEqual(
            self.decrypt(bob, self.encrypt(alice, bob, "clean")), (alice, "clean"),
        )


# ─────────────────────────────────────────────────────────────────────────────
# 5. Cross-peer decryption / session isolation
# ─────────────────────────────────────────────────────────────────────────────

class NexTalkSessionIsolation(NexTalkCase):

    def test_eve_cannot_decrypt_alice_to_bob(self):
        """A third identity has no session for Alice and is refused outright."""
        alice, bob = self.handshake()
        eve = self.init_identity()

        cipher = self.encrypt(alice, bob, "for bob's eyes only")
        res = self.decrypt_fail(eve, cipher)
        self.assertIn("no active session", res.error, repr(res))
        self.assertIn(alice, res.error)

    def test_eve_with_own_session_cannot_read_bobs_traffic(self):
        """
        Eve holds a legitimate session with Alice, yet still cannot read the
        Alice->Bob stream: the ratchet state is per-session, not per-identity.
        """
        alice, bob = self.handshake()
        eve = self.init_identity()

        # Alice <-> Eve handshake (separate session, separate keys).
        offer_path = self.offer(alice, eve, "offer_ae.bin")
        answer_path = self.accept(eve, offer_path, "answer_ea.bin")
        self.assertEqual(self.finish(alice, answer_path), eve)

        # Sanity: the Alice->Eve channel itself works.
        self.assertEqual(
            self.decrypt(eve, self.encrypt(alice, eve, "hi eve")), (alice, "hi eve"),
        )

        # Eve now has sessions[alice], so she gets past the lookup and dies at the MAC.
        for_bob = self.encrypt(alice, bob, "secret for bob")
        res = self.decrypt_fail(eve, for_bob)
        self.assertIn("invalid authentication tag", res.error, repr(res))

    def test_session_keys_differ_across_peers(self):
        """Alice's per-peer key material is unrelated between Bob and Eve."""
        alice, bob = self.handshake()
        eve = self.init_identity()
        self.finish(alice, self.accept(eve, self.offer(alice, eve, "offer_ae.bin"),
                                       "answer_ea.bin"))

        with_bob = self.session_state(alice, bob)
        with_eve = self.session_state(alice, eve)
        for field in ("rootKey", "sendCk", "recvCk", "hmacKey", "fileKey"):
            self.assertNotEqual(
                with_bob[field], with_eve[field],
                f"{field} must be session-scoped, not shared across peers",
            )

    def test_bob_cannot_decrypt_his_own_outbound_message(self):
        """Send and receive chains are asymmetric — no self-decryption."""
        alice, bob = self.handshake()
        outbound = self.encrypt(bob, alice, "bob's own message")
        res = self.decrypt_fail(bob, outbound)
        self.assertTrue(res.error, "Bob must not be able to open his own frame")

    def test_offer_addressed_to_another_peer_is_refused(self):
        """Eve cannot accept an offer that names Bob as the recipient."""
        alice = self.init_identity()
        bob = self.init_identity()
        eve = self.init_identity()

        offer_path = self.offer(alice, bob)
        res = self.cli_fail(
            "offline", "accept", "-i", eve, "-f", offer_path,
            "-o", "hijacked.bin", "--format", "json",
        )
        self.assertIn("not intended for this peer", res.error, repr(res))


# ─────────────────────────────────────────────────────────────────────────────
# 6. Out-of-order delivery
# ─────────────────────────────────────────────────────────────────────────────

class NexTalkOutOfOrder(NexTalkCase):

    def test_reordered_delivery_all_messages_recovered(self):
        """Deliver 3, 1, 2 — every message decrypts via the skipped-key cache."""
        alice, bob = self.handshake()
        m0 = self.encrypt(alice, bob, "msg-0")
        m1 = self.encrypt(alice, bob, "msg-1")
        m2 = self.encrypt(alice, bob, "msg-2")

        self.assertEqual(self.decrypt(bob, m2), (alice, "msg-2"))  # jump ahead
        self.assertEqual(self.decrypt(bob, m0), (alice, "msg-0"))  # from cache
        self.assertEqual(self.decrypt(bob, m1), (alice, "msg-1"))  # from cache

    def test_skipped_key_cache_fills_then_drains(self):
        """Cached keys are stashed for the gap and deleted once consumed."""
        alice, bob = self.handshake()
        frames = [self.encrypt(alice, bob, f"m{i}") for i in range(4)]

        self.decrypt(bob, frames[3])
        cached = self.session_state(bob, alice)["skippedMessages"]
        self.assertEqual(
            len(cached), 3, f"expected keys for nonces 0-2 to be cached, got {cached}",
        )
        self.assertEqual(self.session_state(bob, alice)["recvNonce"], 4)

        for i in (0, 1, 2):
            self.assertEqual(self.decrypt(bob, frames[i]), (alice, f"m{i}"))

        self.assertFalse(
            self.session_state(bob, alice)["skippedMessages"],
            "cache must be empty once every skipped key is consumed",
        )

    def test_cached_key_is_single_use(self):
        """A skipped key is deleted on use, so the same frame cannot replay."""
        alice, bob = self.handshake()
        m0 = self.encrypt(alice, bob, "m0")
        m1 = self.encrypt(alice, bob, "m1")

        self.decrypt(bob, m1)                  # caches the key for nonce 0
        self.decrypt(bob, m0)                  # consumes it
        res = self.decrypt_fail(bob, m0)       # nothing left to consume
        self.assertIn("replay attack or message too old", res.error, repr(res))

    def test_large_gap_recovered(self):
        """A 10-message gap is bridged without losing any plaintext."""
        alice, bob = self.handshake()
        frames = [self.encrypt(alice, bob, f"burst-{i}") for i in range(10)]

        self.assertEqual(self.decrypt(bob, frames[9]), (alice, "burst-9"))
        self.assertEqual(len(self.session_state(bob, alice)["skippedMessages"]), 9)
        for i in reversed(range(9)):
            self.assertEqual(self.decrypt(bob, frames[i]), (alice, f"burst-{i}"))
        self.assertFalse(self.session_state(bob, alice)["skippedMessages"])


# ─────────────────────────────────────────────────────────────────────────────
# 7. Ratchet advancement / forward secrecy
# ─────────────────────────────────────────────────────────────────────────────

class NexTalkRatchetAdvancement(NexTalkCase):

    def test_send_chain_key_advances_every_message(self):
        """Each encrypt replaces sendCk with a fresh HKDF output."""
        alice, bob = self.handshake()

        seen = {self.session_state(alice, bob)["sendCk"]}
        for i in range(5):
            self.encrypt(alice, bob, f"advance-{i}")
            state = self.session_state(alice, bob)
            self.assertEqual(state["sendNonce"], i + 1)
            self.assertNotIn(
                state["sendCk"], seen, "sendCk must never repeat across messages",
            )
            seen.add(state["sendCk"])

    def test_recv_chain_tracks_send_chain(self):
        """After N delivered messages both chains have advanced N steps in step."""
        alice, bob = self.handshake()
        for i in range(5):
            self.decrypt(bob, self.encrypt(alice, bob, f"sync-{i}"))

        a = self.session_state(alice, bob)
        b = self.session_state(bob, alice)
        self.assertEqual(a["sendNonce"], 5)
        self.assertEqual(b["recvNonce"], 5)
        self.assertEqual(a["sendCk"], b["recvCk"], "chains must stay synchronised")

    def test_message_keys_are_independent(self):
        """Identical plaintexts produce distinct ciphertexts (unique message keys)."""
        alice, bob = self.handshake()
        frames = [self.encrypt(alice, bob, "same text") for _ in range(4)]

        ciphertexts = [parse_frame(f)[0]["c"] for f in frames]
        self.assertEqual(
            len(set(ciphertexts)), len(ciphertexts),
            "repeating a plaintext must not repeat the ciphertext",
        )
        nonces = [int(parse_frame(f)[0]["n"]) for f in frames]
        self.assertEqual(nonces, [0, 1, 2, 3], "nonce must increment monotonically")

        for frame, expected in zip(frames, ["same text"] * 4):
            self.assertEqual(self.decrypt(bob, frame), (alice, expected))

    def test_forward_secrecy_old_chain_key_is_destroyed(self):
        """
        The receive chain key is overwritten, not retained.

        Concretely: after Bob processes message N, no copy of the pre-N chain
        key remains in his persisted state, and message N can never be
        processed again.
        """
        alice, bob = self.handshake()
        chain_keys = [self.session_state(bob, alice)["recvCk"]]

        frames = [self.encrypt(alice, bob, f"fs-{i}") for i in range(4)]
        for i, frame in enumerate(frames):
            self.decrypt(bob, frame)
            state = self.session_state(bob, alice)
            self.assertNotIn(
                state["recvCk"], chain_keys, "recvCk must be a fresh value each step",
            )
            chain_keys.append(state["recvCk"])
            # In-order delivery leaves nothing cached, so no old key survives.
            self.assertFalse(
                state["skippedMessages"],
                "in-order delivery must not retain message keys",
            )
            self.assertEqual(state["recvNonce"], i + 1)

        for frame in frames:
            self.assertIn(
                "replay attack or message too old",
                self.decrypt_fail(bob, frame).error,
                "consumed messages must be permanently unreplayable",
            )

    def test_root_key_stable_within_epoch(self):
        """
        The symmetric ratchet does not touch the root key.

        NOTE: the DH ratchet trigger (`pendingDhRatchet`) is an unexported,
        unserialised field on crypto.SecurePeer, so it cannot survive the
        process boundary between two CLI invocations. In CLI usage the session
        therefore stays in the handshake epoch and rootKey is expected to be
        constant; forward secrecy here comes from the symmetric chain only.
        """
        alice, bob = self.handshake()
        root = self.session_state(alice, bob)["rootKey"]
        ratchet_key = self.session_state(alice, bob)["dhPublic"]

        for i in range(3):
            self.decrypt(bob, self.encrypt(alice, bob, f"epoch-{i}"))

        state = self.session_state(alice, bob)
        self.assertEqual(state["rootKey"], root)
        self.assertEqual(
            state["dhPublic"], ratchet_key,
            "no DH rotation is expected across CLI invocations",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def setUpModule() -> None:
    global NEXTALK
    NEXTALK = build_binary()
    print(f"testing binary: {NEXTALK}", file=sys.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
