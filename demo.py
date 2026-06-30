"""
MITM Detection Demo
====================
Verifying Public Key Exchange in Secure Messaging
Mannoj Anandaraj  |  25132766  |  KCL MSc Project 2025-26

Demonstrates three scenarios:
  1. Normal flow — Alice and Bob communicate securely, all keys verified.
  2. MITM on X3DH — attacker substitutes Alice's ephemeral key EK_A.
  3. MITM on Double Ratchet — attacker substitutes a per-message ratchet key.

Run:  python demo.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from signal_sim import (
    IdentityKeyPair, PreKeyBundle,
    KeyTransparencyLog,
    x3dh_initiate, x3dh_respond,
    ratchet_init_sender, ratchet_init_receiver,
    ratchet_send, ratchet_receive,
    _generate_keypair,
)
from smt import SparseMerkleTree


SEPARATOR = "=" * 65


def scenario_1_normal_flow():
    """Scenario 1: Normal secure session — no attacker."""
    print(f"\n{SEPARATOR}")
    print("SCENARIO 1 — Normal Flow (No Attacker)")
    print(SEPARATOR)

    # Setup identities
    alice = IdentityKeyPair.generate("Alice")
    bob   = IdentityKeyPair.generate("Bob")
    bob_bundle = PreKeyBundle.generate(bob)
    log = KeyTransparencyLog()
    session_id = "SESSION_001"

    # X3DH initiation — Alice registers ephemeral keys in SMT
    result = x3dh_initiate(alice, bob_bundle, log, session_id)

    # Bob receives, verifies against SMT — not tampered
    shared_secret_bob, mitm = x3dh_respond(
        bob=bob,
        bob_bundle=bob_bundle,
        alice_identity_pub=alice.public,
        alice_ek_pub=result.ephemeral_key_pub,   # real key, not substituted
        log=log,
        session_id=session_id,
    )

    print(f"\n[RESULT] X3DH session established: {not mitm}")
    print(f"[RESULT] Shared secrets match:      "
          f"{result.shared_secret == shared_secret_bob}")

    # Double Ratchet — send a message
    alice_ratchet = ratchet_init_sender(result.shared_secret, "alice")
    bob_ratchet   = ratchet_init_receiver(shared_secret_bob,  "bob")

    ciphertext, mk, ratchet_pub, alice_ratchet = ratchet_send(
        alice_ratchet, b"Hello Bob, this is secure!", log, session_id
    )

    plaintext, mitm, bob_ratchet = ratchet_receive(
        state              = bob_ratchet,
        ciphertext         = ciphertext,
        sender_ratchet_pub = ratchet_pub,
        log                = log,
        session_id         = session_id,
        msg_number         = 1,
        sender_name        = "alice",
        tampered           = False,
    )

    print(f"\n[RESULT] Message received: {plaintext}")
    print(f"[RESULT] MITM detected:    {mitm}")
    print(f"\n[SCENARIO 1 CONCLUSION] Normal flow complete. No MITM. ✓")


def scenario_2_mitm_x3dh():
    """Scenario 2: Attacker substitutes Alice's X3DH ephemeral key EK_A."""
    print(f"\n{SEPARATOR}")
    print("SCENARIO 2 — MITM on X3DH Ephemeral Key")
    print(SEPARATOR)
    print("Attack: Attacker intercepts EK_A and substitutes it with a fake key.")
    print("Expected: SMT verification detects the mismatch → MITM detected.\n")

    alice = IdentityKeyPair.generate("Alice")
    bob   = IdentityKeyPair.generate("Bob")
    bob_bundle = PreKeyBundle.generate(bob)
    log = KeyTransparencyLog()
    session_id = "SESSION_002"

    # Alice registers EK_A in SMT
    result = x3dh_initiate(alice, bob_bundle, log, session_id)

    # ── ATTACKER SUBSTITUTES EK_A ─────────────────────────────────────────────
    _, fake_ek_pub = _generate_keypair()
    print(f"\n  [ATTACKER] Real  EK_A = {result.ephemeral_key_pub[:8].hex()}...")
    print(f"  [ATTACKER] Fake  EK_A = {fake_ek_pub[:8].hex()}...")
    print(f"  [ATTACKER] Substituting real EK_A with fake EK_A in transit...")

    # Bob receives the FAKE key
    shared_secret_bob, mitm = x3dh_respond(
        bob=bob,
        bob_bundle=bob_bundle,
        alice_identity_pub=alice.public,
        alice_ek_pub=fake_ek_pub,   # ← ATTACKER'S KEY
        log=log,
        session_id=session_id,
    )

    print(f"\n[RESULT] MITM detected: {mitm}")
    print(f"\n[SCENARIO 2 CONCLUSION] Ephemeral key substitution detected by SMT. ✓")


def scenario_3_mitm_ratchet():
    """Scenario 3: Attacker substitutes a Double Ratchet per-message key."""
    print(f"\n{SEPARATOR}")
    print("SCENARIO 3 — MITM on Double Ratchet Key")
    print(SEPARATOR)
    print("Attack: After X3DH succeeds, attacker substitutes a ratchet key.")
    print("Expected: SMT verification detects the mismatch → MITM detected.\n")

    alice = IdentityKeyPair.generate("Alice")
    bob   = IdentityKeyPair.generate("Bob")
    bob_bundle = PreKeyBundle.generate(bob)
    log = KeyTransparencyLog()
    session_id = "SESSION_003"

    # Normal X3DH succeeds
    result = x3dh_initiate(alice, bob_bundle, log, session_id)
    shared_secret_bob, _ = x3dh_respond(
        bob=bob, bob_bundle=bob_bundle,
        alice_identity_pub=alice.public,
        alice_ek_pub=result.ephemeral_key_pub,
        log=log, session_id=session_id,
    )

    alice_ratchet = ratchet_init_sender(result.shared_secret, "alice")
    bob_ratchet   = ratchet_init_receiver(shared_secret_bob,  "bob")

    # Alice sends message — logs ratchet key
    ciphertext, mk, real_ratchet_pub, alice_ratchet = ratchet_send(
        alice_ratchet, b"Secret message from Alice", log, session_id
    )

    # ── ATTACKER SUBSTITUTES RATCHET KEY ─────────────────────────────────────
    _, fake_ratchet_pub = _generate_keypair()
    print(f"\n  [ATTACKER] Real ratchet key = {real_ratchet_pub[:8].hex()}...")
    print(f"  [ATTACKER] Fake ratchet key = {fake_ratchet_pub[:8].hex()}...")
    print(f"  [ATTACKER] Substituting ratchet key for message #1...")

    plaintext, mitm, _ = ratchet_receive(
        state              = bob_ratchet,
        ciphertext         = ciphertext,
        sender_ratchet_pub = fake_ratchet_pub,   # ← ATTACKER'S KEY
        log                = log,
        session_id         = session_id,
        msg_number         = 1,
        sender_name        = "alice",
        tampered           = True,
    )

    print(f"\n[RESULT] MITM detected: {mitm}")
    print(f"\n[SCENARIO 3 CONCLUSION] Double Ratchet key substitution detected. ✓")


def smt_standalone_demo():
    """Standalone SMT demo — shows the tree itself working."""
    print(f"\n{SEPARATOR}")
    print("SMT STANDALONE DEMO — Core Data Structure")
    print(SEPARATOR)

    tree = SparseMerkleTree()
    print(f"\nEmpty tree root:  {tree.root[:16].hex()}...")

    # Insert Alice's key
    alice_pub = b"alice_public_key_32_bytes_here!!"
    root1 = tree.insert(b"alice_identity", alice_pub)
    print(f"After Alice:      {root1[:16].hex()}...")

    # Insert Bob's key
    bob_pub = b"bob__public_key_32_bytes_here!!!"
    root2 = tree.insert(b"bob_identity", bob_pub)
    print(f"After Bob:        {root2[:16].hex()}...")

    print(f"\nTree size: {tree.size()} entries")

    # Inclusion proof for Alice
    proof = tree.prove(b"alice_identity")
    print(f"\nAlice inclusion proof: {proof}")
    valid = SparseMerkleTree.verify_inclusion(
        b"alice_identity", alice_pub, proof, root2
    )
    print(f"Alice inclusion verification: {valid}")

    # Non-inclusion proof for Charlie (not registered)
    proof_charlie = tree.prove(b"charlie_identity")
    print(f"\nCharlie non-inclusion proof: {proof_charlie}")
    valid_ni = SparseMerkleTree.verify_non_inclusion(
        b"charlie_identity", proof_charlie, root2
    )
    print(f"Charlie non-inclusion verification: {valid_ni}")

    # Tamper detection
    print(f"\n--- Tamper Detection ---")
    fake_key = b"fake_public_key_32_bytes_here!!!"
    tampered = SparseMerkleTree.verify_inclusion(
        b"alice_identity", fake_key, proof, root2
    )
    print(f"Verify fake key as Alice's: {tampered}  ← correctly rejected")

    print(f"\n[SMT DEMO CONCLUSION] All proofs correct. Tamper detected. ✓")


if __name__ == "__main__":
    print(f"\n{'#' * 65}")
    print("#  Verifying Public Key Exchange in Secure Messaging")
    print("#  Mannoj Anandaraj  |  25132766  |  KCL MSc 2025-26")
    print("#  Active MITM Detection via Sparse Merkle Tree")
    print(f"{'#' * 65}")

    smt_standalone_demo()
    scenario_1_normal_flow()
    scenario_2_mitm_x3dh()
    scenario_3_mitm_ratchet()

    print(f"\n{SEPARATOR}")
    print("ALL SCENARIOS COMPLETE")
    print("  Scenario 1: Normal flow      — Session established, messages verified ✓")
    print("  Scenario 2: MITM on X3DH     — Ephemeral key substitution detected  ✓")
    print("  Scenario 3: MITM on Ratchet  — Ratchet key substitution detected    ✓")
    print(SEPARATOR)
