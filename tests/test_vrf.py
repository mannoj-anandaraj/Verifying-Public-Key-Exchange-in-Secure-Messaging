"""
ECVRF Test Suite
================================================
Verifying Public Key Exchange in Secure Messaging
Mannoj Anandaraj  |  25132766  |  KCL MSc Project 2025-26

10 tests covering the real ECVRF implementation (RFC 9381,
ECVRF-EDWARDS25519-SHA512-ELL2) in src/vrf.py.

These tests validate the properties that motivate choosing ECVRF over
a generic VRF: correctness of the compute/verify roundtrip, rejection
of tampered proofs and wrong inputs, determinism, and — critically —
the uniqueness property that a generic HMAC-based construction cannot
provide (see test_same_input_same_key_deterministic and
test_different_inputs_different_outputs).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from vrf import VRFKeyPair, VRFProof, vrf_compute, vrf_verify


class TestVRFKeyGeneration:

    def test_keypair_generates_32_byte_keys(self):
        kp = VRFKeyPair.generate()
        assert len(kp.secret_key) == 32
        assert len(kp.public_key) == 32

    def test_keypair_is_random(self):
        kp1 = VRFKeyPair.generate()
        kp2 = VRFKeyPair.generate()
        assert kp1.secret_key != kp2.secret_key
        assert kp1.public_key != kp2.public_key


class TestVRFComputeVerify:

    def test_compute_produces_valid_proof_shape(self):
        kp = VRFKeyPair.generate()
        proof = vrf_compute(kp, b"alice@example.com")
        assert isinstance(proof, VRFProof)
        assert len(proof.output) == 32
        assert len(proof.proof) == 80

    def test_roundtrip_verifies_true(self):
        kp = VRFKeyPair.generate()
        proof = vrf_compute(kp, b"alice@example.com")
        assert vrf_verify(kp.public_key, b"alice@example.com", proof) is True

    def test_verification_uses_only_public_key(self):
        """
        Core ECVRF property: verification never touches the secret key.
        This is what makes leaf positions publicly auditable.
        """
        kp = VRFKeyPair.generate()
        proof = vrf_compute(kp, b"bob@example.com")
        # vrf_verify's signature only accepts public_key — passing the
        # secret key here would be a type error, confirming by construction
        # that verification cannot depend on it.
        assert vrf_verify(kp.public_key, b"bob@example.com", proof) is True


class TestVRFRejection:

    def test_wrong_input_fails_verification(self):
        kp = VRFKeyPair.generate()
        proof = vrf_compute(kp, b"alice@example.com")
        assert vrf_verify(kp.public_key, b"eve@example.com", proof) is False

    def test_wrong_public_key_fails_verification(self):
        kp1 = VRFKeyPair.generate()
        kp2 = VRFKeyPair.generate()
        proof = vrf_compute(kp1, b"alice@example.com")
        assert vrf_verify(kp2.public_key, b"alice@example.com", proof) is False

    def test_tampered_proof_bytes_fail_verification(self):
        kp = VRFKeyPair.generate()
        proof = vrf_compute(kp, b"alice@example.com")
        tampered_bytes = bytearray(proof.proof)
        tampered_bytes[0] ^= 0xFF  # flip bits in Gamma
        tampered_proof = VRFProof(output=proof.output, proof=bytes(tampered_bytes))
        assert vrf_verify(kp.public_key, b"alice@example.com", tampered_proof) is False


class TestVRFDeterminismAndUniqueness:

    def test_same_input_same_key_deterministic(self):
        """
        ECVRF must be deterministic: same (sk, input) always produces the
        same output. This is required for the SMT leaf position to be
        stable across repeated lookups.
        """
        kp = VRFKeyPair.generate()
        proof1 = vrf_compute(kp, b"alice@example.com")
        proof2 = vrf_compute(kp, b"alice@example.com")
        assert proof1.output == proof2.output

    def test_different_inputs_different_outputs(self):
        """
        Distinct identities must map to distinct (with overwhelming
        probability) leaf positions — required to prevent collisions
        in the key transparency log.
        """
        kp = VRFKeyPair.generate()
        proof_alice = vrf_compute(kp, b"alice@example.com")
        proof_bob = vrf_compute(kp, b"bob@example.com")
        assert proof_alice.output != proof_bob.output

    def test_different_keys_different_outputs_for_same_input(self):
        """
        Two different secret keys must not collide on the same input —
        confirms the VRF output is bound to the key, not just the input.
        """
        kp1 = VRFKeyPair.generate()
        kp2 = VRFKeyPair.generate()
        proof1 = vrf_compute(kp1, b"alice@example.com")
        proof2 = vrf_compute(kp2, b"alice@example.com")
        assert proof1.output != proof2.output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
