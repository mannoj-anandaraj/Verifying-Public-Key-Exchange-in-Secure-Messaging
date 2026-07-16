"""
Real Cryptography Test Suite
================================================
Verifying Public Key Exchange in Secure Messaging
Mannoj Anandaraj  |  25132766  |  KCL MSc Project 2025-26

10 tests covering the real cryptographic primitives in src/signal_sim.py:
Curve25519 key generation, X25519 Diffie-Hellman, HKDF-SHA256 key
derivation, and AES-256-GCM authenticated encryption — plus full
end-to-end X3DH and Double Ratchet integration tests using real keys.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from signal_sim import (
    _generate_keypair, _dh, _hkdf, _encrypt, _decrypt,
    IdentityKeyPair, PreKeyBundle, KeyTransparencyLog,
    x3dh_initiate, x3dh_respond,
    ratchet_init_sender, ratchet_init_receiver, ratchet_send, ratchet_receive,
)


class TestCurve25519Primitives:

    def test_keypair_generates_32_byte_keys(self):
        priv, pub = _generate_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_dh_is_symmetric(self):
        """
        Core Diffie-Hellman correctness: DH(a_priv, b_pub) == DH(b_priv, a_pub).
        This is what allows both parties to derive the same shared secret.
        """
        a_priv, a_pub = _generate_keypair()
        b_priv, b_pub = _generate_keypair()
        shared_a = _dh(a_priv, b_pub)
        shared_b = _dh(b_priv, a_pub)
        assert shared_a == shared_b
        assert len(shared_a) == 32

    def test_dh_differs_for_different_keypairs(self):
        a_priv, a_pub = _generate_keypair()
        b_priv, b_pub = _generate_keypair()
        c_priv, c_pub = _generate_keypair()
        assert _dh(a_priv, b_pub) != _dh(a_priv, c_pub)


class TestHKDF:

    def test_hkdf_deterministic(self):
        ikm = b"shared_secret_material"
        out1 = _hkdf(ikm, b"info_string")
        out2 = _hkdf(ikm, b"info_string")
        assert out1 == out2

    def test_hkdf_differs_by_info(self):
        """Different 'info' context strings must derive different keys —
        this is what separates root key vs chain key derivation."""
        ikm = b"shared_secret_material"
        rk = _hkdf(ikm, b"RATCHET_INIT_RK")
        ck = _hkdf(ikm, b"RATCHET_INIT_CK")
        assert rk != ck

    def test_hkdf_respects_length(self):
        out = _hkdf(b"ikm", b"info", length=16)
        assert len(out) == 16
        out_default = _hkdf(b"ikm", b"info")
        assert len(out_default) == 32


class TestAESGCM:

    def test_encrypt_decrypt_roundtrip(self):
        key = b"\x00" * 32
        plaintext = b"hello bob, this is alice"
        ciphertext = _encrypt(key, plaintext)
        recovered = _decrypt(key, ciphertext)
        assert recovered == plaintext

    def test_decrypt_fails_on_tampered_ciphertext(self):
        """AES-GCM's authentication tag must reject tampered ciphertext —
        this is what detects message-level tampering, distinct from
        SMT-level key-substitution detection."""
        key = b"\x00" * 32
        ciphertext = bytearray(_encrypt(key, b"original message"))
        ciphertext[20] ^= 0xFF  # flip a byte in the ciphertext body
        with pytest.raises(ValueError):
            _decrypt(key, bytes(ciphertext))

    def test_nonce_is_random_per_encryption(self):
        """Each encryption must use a fresh nonce — reused nonces under
        GCM catastrophically break confidentiality."""
        key = b"\x00" * 32
        ct1 = _encrypt(key, b"same message")
        ct2 = _encrypt(key, b"same message")
        assert ct1[:12] != ct2[:12]  # nonce is the first 12 bytes


class TestEndToEndIntegration:

    def test_full_x3dh_handshake_shared_secret_matches(self):
        """Alice and Bob must derive the identical shared secret via X3DH
        using only real Curve25519 operations."""
        log = KeyTransparencyLog()
        alice = IdentityKeyPair.generate("alice")
        bob = IdentityKeyPair.generate("bob")
        bob_bundle = PreKeyBundle.generate(bob)

        result = x3dh_initiate(alice, bob_bundle, log, "test_session")
        bob_secret, mitm = x3dh_respond(
            bob, bob_bundle, alice.public, result.ephemeral_key_pub,
            log, "test_session",
        )

        assert mitm is False
        assert bob_secret == result.shared_secret

    def test_full_double_ratchet_message_roundtrip(self):
        """A message sent via ratchet_send must decrypt correctly via
        ratchet_receive, with the ratchet key verified against the SMT log."""
        log = KeyTransparencyLog()
        alice = IdentityKeyPair.generate("alice")
        bob = IdentityKeyPair.generate("bob")
        bob_bundle = PreKeyBundle.generate(bob)

        result = x3dh_initiate(alice, bob_bundle, log, "test_session")
        shared_secret, _ = x3dh_respond(
            bob, bob_bundle, alice.public, result.ephemeral_key_pub,
            log, "test_session",
        )

        alice_state = ratchet_init_sender(shared_secret, "alice")
        bob_state = ratchet_init_receiver(shared_secret, "bob")

        ciphertext, _, ratchet_pub, alice_state = ratchet_send(
            alice_state, b"hello bob", log, "test_session",
        )
        plaintext, mitm, bob_state = ratchet_receive(
            bob_state, ciphertext, ratchet_pub, log, "test_session",
            alice_state.msg_number, "alice",
        )

        assert mitm is False
        assert plaintext == b"hello bob"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
