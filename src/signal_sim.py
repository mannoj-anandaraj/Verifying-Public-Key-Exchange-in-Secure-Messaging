"""
Signal Protocol Simulation with SMT Key Logging
=================================================
Verifying Public Key Exchange in Secure Messaging
Mannoj Anandaraj  |  25132766  |  KCL MSc Project 2025-26

Real cryptographic implementation using:
  - Curve25519 (X25519) for all key pairs and DH operations   [PyNaCl]
  - HKDF-SHA256 (RFC 5869) for key derivation                 [PyNaCl]
  - AES-256-GCM for authenticated encryption                  [PyCryptodome]

This simulates the key exchange points in X3DH and Double Ratchet
where ephemeral keys are generated, transmitted, and logged to the
Sparse Merkle Tree.

This is NOT a full Signal implementation — it simulates the
cryptographic key exchange structure to demonstrate where
the SMT logging integrates and how MITM detection works.

Key exchange points logged to SMT:
  1. X3DH: Alice's ephemeral key EK_A (one-time)
  2. X3DH: Bob's one-time prekey OPK_B (consumed per session)
  3. Double Ratchet: per-message DH ratchet public keys

References:
  [2] Marlinspike & Perrin — The X3DH Key Agreement Protocol
  [3] Perrin & Marlinspike — The Double Ratchet Algorithm
  [8] Dowling & Hale — ACKA: Active MitM Detection (2023)
"""

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Real cryptographic libraries
from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey, Box
from nacl.bindings import crypto_scalarmult
import nacl.hash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from smt import SparseMerkleTree, WindowedSparseMerkleTree, SMTProof


# ── Real Curve25519 / X25519 primitives ──────────────────────────────────────

def _generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a real Curve25519 key pair.
    Returns (private_key_bytes, public_key_bytes) — both 32 bytes.

    Uses PyNaCl's X25519 implementation, the same curve Signal uses
    for X3DH and Double Ratchet key operations.
    """
    sk = X25519PrivateKey.generate()
    return bytes(sk), bytes(sk.public_key)


def _dh(private_key: bytes, public_key: bytes) -> bytes:
    """
    Real X25519 Diffie-Hellman operation.
    Returns 32-byte shared output = X25519(private, public).

    This is the actual DH function used in Signal's X3DH and
    Double Ratchet — crypto_scalarmult is the PyNaCl binding
    for X25519 scalar multiplication.
    """
    return crypto_scalarmult(private_key, public_key)


def _hkdf(ikm: bytes, info: bytes, salt: bytes = None, length: int = 32) -> bytes:
    """
    Real HKDF-SHA256 (RFC 5869).

    Extract-then-expand:
      PRK  = HMAC-SHA256(salt, IKM)      [extract]
      OKM  = HMAC-SHA256(PRK, info||ctr) [expand]
    """
    # Extract
    if salt is None:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand
    output = b""
    prev = b""
    ctr = 1
    while len(output) < length:
        prev = hmac.new(prk, prev + info + bytes([ctr]), hashlib.sha256).digest()
        output += prev
        ctr += 1
    return output[:length]


def _encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Real AES-256-GCM authenticated encryption.
    Returns nonce (12 bytes) || ciphertext || tag (16 bytes).
    """
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag


def _decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Real AES-256-GCM authenticated decryption.
    Raises ValueError if authentication tag fails.
    """
    nonce = ciphertext[:12]
    tag   = ciphertext[-16:]
    ct    = ciphertext[12:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ── Key types ─────────────────────────────────────────────────────────────────

@dataclass
class IdentityKeyPair:
    """
    Long-term identity key — never rotates.
    Real Curve25519 key pair generated via PyNaCl.
    """
    private: bytes
    public:  bytes
    owner:   str

    @classmethod
    def generate(cls, owner: str) -> "IdentityKeyPair":
        priv, pub = _generate_keypair()
        return cls(private=priv, public=pub, owner=owner)


@dataclass
class PreKeyBundle:
    """
    Bob's prekey bundle — uploaded to server before any session.
    Contains the keys X3DH needs to establish a shared secret
    even when Bob is offline.

    All keys are real Curve25519 key pairs.
    """
    identity_key_pub:     bytes   # IK_B  — long-term
    signed_prekey_pub:    bytes   # SPK_B — rotated periodically
    signed_prekey_priv:   bytes
    one_time_prekey_pub:  bytes   # OPK_B — consumed once per session
    one_time_prekey_priv: bytes
    owner: str

    @classmethod
    def generate(cls, identity: IdentityKeyPair) -> "PreKeyBundle":
        spk_priv, spk_pub = _generate_keypair()
        opk_priv, opk_pub = _generate_keypair()
        return cls(
            identity_key_pub      = identity.public,
            signed_prekey_pub     = spk_pub,
            signed_prekey_priv    = spk_priv,
            one_time_prekey_pub   = opk_pub,
            one_time_prekey_priv  = opk_priv,
            owner = identity.owner,
        )


@dataclass
class X3DHResult:
    """Output of the X3DH key exchange."""
    shared_secret:    bytes   # SK — used to initialise Double Ratchet
    ephemeral_key_pub: bytes  # EK_A — Alice's ephemeral key (logged to SMT)
    session_id:       str


@dataclass
class RatchetState:
    """State for one party's Double Ratchet session."""
    root_key:      bytes
    chain_key:     bytes
    ratchet_priv:  bytes
    ratchet_pub:   bytes   # current DH ratchet public key (logged to SMT)
    remote_pub:    Optional[bytes]
    msg_number:    int = 0
    owner:         str = ""


@dataclass
class LoggedKeyEvent:
    """
    A key exchange event recorded in the SMT log.
    Captures everything needed for MITM detection.
    """
    event_type:  str     # "X3DH_EPHEMERAL", "X3DH_OPK", "RATCHET"
    owner:       str
    public_key:  bytes   # the key being logged
    session_id:  str
    timestamp:   float
    smt_root:    bytes   # root hash AFTER this key was logged


# ── SMT Key Transparency Log ──────────────────────────────────────────────────

class KeyTransparencyLog:
    """
    The core contribution of this project.

    Records every ephemeral key at the point of exchange in a
    tamper-evident Sparse Merkle Tree. Any substitution by an
    active MITM creates a verifiable inconsistency.

    This implements the logging component of the ACKA framework
    defined by Dowling & Hale [8], using the SMT properties
    formalised by Dowling et al. [9].
    """

    def __init__(self, window_size: Optional[int] = None):
        """
        window_size=None (default) preserves the original unbounded
        behaviour — every key logged stays live in the tree forever.
        This keeps all existing call sites (demo.py, tests) unchanged.

        window_size=N switches to WindowedSparseMerkleTree, bounding the
        live tree to the N most recently logged keys. The full event
        history is still kept in self.events regardless of windowing,
        since that list is cheap (no tree recomputation) and is what
        Phase 4 benchmarking and evaluation replay against.
        """
        self.tree: SparseMerkleTree = (
            WindowedSparseMerkleTree(window_size) if window_size else SparseMerkleTree()
        )
        self.window_size = window_size
        self.events: List[LoggedKeyEvent] = []

    def log_key(
        self,
        owner: str,
        public_key: bytes,
        session_id: str,
        event_type: str = "KEY",
    ) -> LoggedKeyEvent:
        """
        Log an ephemeral public key into the SMT.
        The SMT key is derived from (owner, session_id, event_type)
        to ensure each distinct key exchange event has a unique position.
        """
        log_key = _sha256(
            owner.encode() + b":" +
            session_id.encode() + b":" +
            event_type.encode()
        )
        new_root = self.tree.insert(log_key, public_key)

        event = LoggedKeyEvent(
            event_type = event_type,
            owner      = owner,
            public_key = public_key,
            session_id = session_id,
            timestamp  = time.time(),
            smt_root   = new_root,
        )
        self.events.append(event)
        print(f"  [LOG] {event_type} for {owner} | "
              f"key={public_key[:6].hex()}... | "
              f"root={new_root[:6].hex()}...")
        return event

    def generate_proof(
        self,
        owner: str,
        session_id: str,
        event_type: str = "KEY",
    ) -> SMTProof:
        """Generate a proof that a key was (or was not) logged."""
        log_key = _sha256(
            owner.encode() + b":" +
            session_id.encode() + b":" +
            event_type.encode()
        )
        return self.tree.prove(log_key)

    def verify_key(
        self,
        owner: str,
        public_key: bytes,
        session_id: str,
        event_type: str = "KEY",
        expected_root: bytes = None,
    ) -> bool:
        """
        Verify that a received public_key matches what is in the log.
        This is what Bob calls when he receives a key from Alice.
        Returns True if the key is valid, False if MITM detected.
        """
        log_key = _sha256(
            owner.encode() + b":" +
            session_id.encode() + b":" +
            event_type.encode()
        )
        proof = self.tree.prove(log_key)
        root  = expected_root or self.tree.root

        if proof.is_member:
            return SparseMerkleTree.verify_inclusion(log_key, public_key, proof, root)
        return False

    @property
    def current_root(self) -> bytes:
        return self.tree.root


# ── X3DH Session Initiation ───────────────────────────────────────────────────

def x3dh_initiate(
    alice: IdentityKeyPair,
    bob_bundle: PreKeyBundle,
    log: KeyTransparencyLog,
    session_id: str,
) -> X3DHResult:
    """
    Alice initiates an X3DH session with Bob using real Curve25519 keys.

    Real X3DH key exchange (RFC / Signal spec):
      DH1 = X25519(IK_A_priv,  SPK_B_pub)
      DH2 = X25519(EK_A_priv,  IK_B_pub)
      DH3 = X25519(EK_A_priv,  SPK_B_pub)
      DH4 = X25519(EK_A_priv,  OPK_B_pub)
      SK  = HKDF-SHA256(DH1 || DH2 || DH3 || DH4)

    EK_A is logged to the SMT immediately after generation.
    """
    print(f"\n[X3DH] Alice initiating session with Bob (session={session_id})")

    # Alice generates real Curve25519 ephemeral key pair EK_A
    ek_priv, ek_pub = _generate_keypair()
    print(f"  [X3DH] Alice generated EK_A = {ek_pub[:8].hex()}...")

    # Log EK_A to the SMT
    log.log_key(
        owner      = f"alice_ek_{session_id}",
        public_key = ek_pub,
        session_id = session_id,
        event_type = "X3DH_EPHEMERAL",
    )

    # Log Bob's OPK_B being consumed
    log.log_key(
        owner      = f"bob_opk_{session_id}",
        public_key = bob_bundle.one_time_prekey_pub,
        session_id = session_id,
        event_type = "X3DH_OPK",
    )

    # Real X25519 DH operations
    dh1 = _dh(alice.private,  bob_bundle.signed_prekey_pub)    # DH(IK_A,  SPK_B)
    dh2 = _dh(ek_priv,        bob_bundle.identity_key_pub)     # DH(EK_A,  IK_B)
    dh3 = _dh(ek_priv,        bob_bundle.signed_prekey_pub)    # DH(EK_A,  SPK_B)
    dh4 = _dh(ek_priv,        bob_bundle.one_time_prekey_pub)  # DH(EK_A,  OPK_B)

    # HKDF-SHA256 to derive shared secret
    shared_secret = _hkdf(
        ikm  = dh1 + dh2 + dh3 + dh4,
        info = b"X3DH_SK_" + session_id.encode(),
    )
    print(f"  [X3DH] Shared secret derived: {shared_secret[:8].hex()}...")
    print(f"  [SMT]  Root after X3DH logging: {log.current_root[:8].hex()}...")

    return X3DHResult(
        shared_secret     = shared_secret,
        ephemeral_key_pub = ek_pub,
        session_id        = session_id,
    )


def x3dh_respond(
    bob: IdentityKeyPair,
    bob_bundle: PreKeyBundle,
    alice_identity_pub: bytes,
    alice_ek_pub: bytes,
    log: KeyTransparencyLog,
    session_id: str,
    tampered: bool = False,
) -> Tuple[Optional[bytes], bool]:
    """
    Bob receives Alice's X3DH initiation and verifies against the SMT log.
    Returns (shared_secret, mitm_detected).
    If tampered=True, simulates an attacker substituting alice_ek_pub.
    """
    print(f"\n[X3DH] Bob responding to Alice's session (session={session_id})")

    # ── MITM detection ────────────────────────────────────────────────────────
    print(f"  [VERIFY] Checking Alice's EK_A against SMT log...")

    key_in_log = log.verify_key(
        owner         = f"alice_ek_{session_id}",
        public_key    = alice_ek_pub,
        session_id    = session_id,
        event_type    = "X3DH_EPHEMERAL",
        expected_root = log.current_root,
    )

    if not key_in_log:
        print(f"  [!!! MITM DETECTED !!!] EK_A verification FAILED")
        print(f"  [!!! MITM DETECTED !!!] Received key does not match SMT log")
        print(f"  [!!! MITM DETECTED !!!] Session ABORTED")
        return None, True

    print(f"  [VERIFY] EK_A verified against SMT log — OK")

    # Real X25519 DH operations (mirror of Alice's)
    dh1 = _dh(bob_bundle.signed_prekey_priv,   alice_identity_pub)  # DH(SPK_B, IK_A)
    dh2 = _dh(bob.private,                      alice_ek_pub)        # DH(IK_B,  EK_A)
    dh3 = _dh(bob_bundle.signed_prekey_priv,    alice_ek_pub)        # DH(SPK_B, EK_A)
    dh4 = _dh(bob_bundle.one_time_prekey_priv,  alice_ek_pub)        # DH(OPK_B, EK_A)

    shared_secret = _hkdf(
        ikm  = dh1 + dh2 + dh3 + dh4,
        info = b"X3DH_SK_" + session_id.encode(),
    )
    print(f"  [X3DH] Shared secret derived: {shared_secret[:8].hex()}...")

    return shared_secret, False


# ── Double Ratchet ────────────────────────────────────────────────────────────

def ratchet_init_sender(shared_secret: bytes, owner: str) -> RatchetState:
    """Initialise Alice's ratchet state from the X3DH shared secret."""
    rk = _hkdf(shared_secret, b"RATCHET_INIT_RK")
    ck = _hkdf(shared_secret, b"RATCHET_INIT_CK")
    priv, pub = _generate_keypair()   # real Curve25519 ratchet key
    return RatchetState(
        root_key     = rk,
        chain_key    = ck,
        ratchet_priv = priv,
        ratchet_pub  = pub,
        remote_pub   = None,
        owner        = owner,
    )


def ratchet_init_receiver(shared_secret: bytes, owner: str) -> RatchetState:
    """Initialise Bob's ratchet state."""
    return ratchet_init_sender(shared_secret, owner)


def ratchet_send(
    state: RatchetState,
    plaintext: bytes,
    log: KeyTransparencyLog,
    session_id: str,
) -> Tuple[bytes, bytes, bytes, RatchetState]:
    """
    Send a message using the Double Ratchet.
    Logs the current DH ratchet public key to the SMT.
    Returns (ciphertext, message_key, ratchet_pub, new_state).
    """
    state.msg_number += 1
    event_type = f"RATCHET_MSG_{state.msg_number}"

    # Log current DH ratchet public key — this is the key being attacked in Scenario 3
    log.log_key(
        owner      = f"{state.owner}_{session_id}",
        public_key = state.ratchet_pub,
        session_id = session_id,
        event_type = event_type,
    )

    # Derive message key from chain key using HKDF
    message_key   = _hkdf(state.chain_key, b"MSG_KEY_"    + state.msg_number.to_bytes(4, "big"))
    new_chain_key = _hkdf(state.chain_key, b"CHAIN_ADVANCE" + state.msg_number.to_bytes(4, "big"))

    new_state = RatchetState(
        root_key     = state.root_key,
        chain_key    = new_chain_key,
        ratchet_priv = state.ratchet_priv,
        ratchet_pub  = state.ratchet_pub,
        remote_pub   = state.remote_pub,
        msg_number   = state.msg_number,
        owner        = state.owner,
    )

    # Real AES-256-GCM encryption
    ciphertext = _encrypt(message_key, plaintext)
    return ciphertext, message_key, state.ratchet_pub, new_state


def ratchet_receive(
    state: RatchetState,
    ciphertext: bytes,
    sender_ratchet_pub: bytes,
    log: KeyTransparencyLog,
    session_id: str,
    msg_number: int,
    sender_name: str,
    tampered: bool = False,
) -> Tuple[Optional[bytes], bool, RatchetState]:
    """
    Receive and verify a message.
    Verifies the sender's DH ratchet public key against the SMT log.
    Returns (plaintext, mitm_detected, new_state).
    """
    print(f"\n  [RATCHET] {state.owner} verifying msg #{msg_number} ratchet key...")

    event_type = f"RATCHET_MSG_{msg_number}"
    key_valid  = log.verify_key(
        owner         = f"{sender_name}_{session_id}",
        public_key    = sender_ratchet_pub,
        session_id    = session_id,
        event_type    = event_type,
        expected_root = log.current_root,
    )

    if not key_valid:
        print(f"  [!!! MITM DETECTED !!!] Ratchet key verification FAILED on msg #{msg_number}")
        return None, True, state

    print(f"  [VERIFY] Ratchet key for msg #{msg_number} verified — OK")

    # Derive message key (mirrors sender)
    message_key = _hkdf(state.chain_key, b"MSG_KEY_" + msg_number.to_bytes(4, "big"))

    # Real AES-256-GCM decryption
    try:
        plaintext = _decrypt(message_key, ciphertext)
    except ValueError:
        print(f"  [!!! MITM DETECTED !!!] AES-GCM authentication tag FAILED — message tampered")
        return None, True, state

    new_state = RatchetState(
        root_key     = state.root_key,
        chain_key    = _hkdf(state.chain_key, b"CHAIN_ADVANCE" + msg_number.to_bytes(4, "big")),
        ratchet_priv = state.ratchet_priv,
        ratchet_pub  = state.ratchet_pub,
        remote_pub   = sender_ratchet_pub,
        msg_number   = state.msg_number,
        owner        = state.owner,
    )

    return plaintext, False, new_state
