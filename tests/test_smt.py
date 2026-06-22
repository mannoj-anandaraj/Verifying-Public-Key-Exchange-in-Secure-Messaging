"""
Unit Tests — Sparse Merkle Tree
================================
Verifying Public Key Exchange in Secure Messaging
Mannoj Anandaraj  |  25132766  |  KCL MSc Project 2025-26

Tests cover:
  - Basic insert, get, delete
  - Root changes on every modification
  - Inclusion proof generation and verification
  - Non-inclusion proof generation and verification
  - Tamper detection (wrong value, wrong key)
  - Empty tree properties
  - Multiple entries
  - Proof consistency across operations

Run:  python -m pytest tests/ -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import hashlib
import pytest
from smt import SparseMerkleTree, EMPTY, DEPTH, _sha256


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tree():
    return SparseMerkleTree()

@pytest.fixture
def populated_tree():
    t = SparseMerkleTree()
    t.insert(b"alice", b"alice_public_key_data_32_bytes!!")
    t.insert(b"bob",   b"bob___public_key_data_32_bytes!!")
    return t


# ── Basic operations ──────────────────────────────────────────────────────────

class TestBasicOperations:

    def test_empty_tree_root(self, tree):
        """Empty tree has the precomputed empty root hash."""
        assert tree.root == EMPTY[DEPTH]

    def test_empty_tree_size(self, tree):
        assert tree.size() == 0

    def test_insert_returns_root(self, tree):
        root = tree.insert(b"key1", b"value1")
        assert isinstance(root, bytes) and len(root) == 32

    def test_insert_changes_root(self, tree):
        root_before = tree.root
        tree.insert(b"key1", b"value1")
        assert tree.root != root_before

    def test_get_after_insert(self, tree):
        tree.insert(b"key1", b"value1")
        assert tree.get(b"key1") == b"value1"

    def test_get_nonexistent_returns_none(self, tree):
        assert tree.get(b"nonexistent") is None

    def test_contains_after_insert(self, tree):
        tree.insert(b"alice", b"alice_key")
        assert tree.contains(b"alice")
        assert not tree.contains(b"bob")

    def test_update_changes_root(self, tree):
        tree.insert(b"key1", b"value1")
        root_after_insert = tree.root
        tree.update(b"key1", b"value2")
        assert tree.root != root_after_insert

    def test_update_retrieval(self, tree):
        tree.insert(b"key1", b"value1")
        tree.update(b"key1", b"value2")
        assert tree.get(b"key1") == b"value2"

    def test_delete_removes_entry(self, tree):
        tree.insert(b"key1", b"value1")
        tree.delete(b"key1")
        assert tree.get(b"key1") is None
        assert not tree.contains(b"key1")

    def test_delete_restores_root(self, tree):
        """Deleting the only entry should restore the empty root."""
        empty_root = tree.root
        tree.insert(b"key1", b"value1")
        tree.delete(b"key1")
        assert tree.root == empty_root

    def test_size_tracking(self, tree):
        tree.insert(b"a", b"av")
        tree.insert(b"b", b"bv")
        tree.insert(b"c", b"cv")
        assert tree.size() == 3
        tree.delete(b"b")
        assert tree.size() == 2

    def test_multiple_entries_independent_roots(self, tree):
        """Each insert should produce a unique root."""
        roots = set()
        for i in range(10):
            root = tree.insert(f"key{i}".encode(), f"value{i}".encode())
            roots.add(root)
        assert len(roots) == 10

    def test_deterministic_root(self):
        """Same inserts in same order should produce identical roots."""
        t1 = SparseMerkleTree()
        t2 = SparseMerkleTree()
        entries = [(b"alice", b"key_a"), (b"bob", b"key_b"), (b"charlie", b"key_c")]
        for k, v in entries:
            t1.insert(k, v)
            t2.insert(k, v)
        assert t1.root == t2.root


# ── Inclusion proofs ──────────────────────────────────────────────────────────

class TestInclusionProofs:

    def test_prove_existing_key_is_member(self, populated_tree):
        proof = populated_tree.prove(b"alice")
        assert proof.is_member is True

    def test_prove_returns_256_siblings(self, populated_tree):
        proof = populated_tree.prove(b"alice")
        assert len(proof.siblings) == DEPTH

    def test_inclusion_verify_correct_value(self, populated_tree):
        proof = populated_tree.prove(b"alice")
        valid = SparseMerkleTree.verify_inclusion(
            b"alice",
            b"alice_public_key_data_32_bytes!!",
            proof,
            populated_tree.root,
        )
        assert valid is True

    def test_inclusion_verify_wrong_value(self, populated_tree):
        """Tampered value should fail verification."""
        proof = populated_tree.prove(b"alice")
        valid = SparseMerkleTree.verify_inclusion(
            b"alice",
            b"WRONG_PUBLIC_KEY_DATA_32_BYTES!!",
            proof,
            populated_tree.root,
        )
        assert valid is False

    def test_inclusion_verify_wrong_root(self, populated_tree):
        """Wrong root should fail verification."""
        proof = populated_tree.prove(b"alice")
        fake_root = b"\xff" * 32
        valid = SparseMerkleTree.verify_inclusion(
            b"alice",
            b"alice_public_key_data_32_bytes!!",
            proof,
            fake_root,
        )
        assert valid is False

    def test_inclusion_verify_wrong_key(self, populated_tree):
        """Proof generated for alice should not verify for bob."""
        proof = populated_tree.prove(b"alice")
        valid = SparseMerkleTree.verify_inclusion(
            b"bob",
            b"alice_public_key_data_32_bytes!!",
            proof,
            populated_tree.root,
        )
        assert valid is False

    def test_proof_consistency_after_insert(self, tree):
        """Proof generated before and after another insert should reflect roots correctly."""
        tree.insert(b"alice", b"alice_key_value_placeholder_32b!")
        proof_alice = tree.prove(b"alice")
        root_before = tree.root

        tree.insert(b"charlie", b"charlie_key_placeholder_32bytes!")
        root_after = tree.root

        # Old proof validates against old root
        valid_old = SparseMerkleTree.verify_inclusion(
            b"alice", b"alice_key_value_placeholder_32b!", proof_alice, root_before
        )
        assert valid_old is True

        # Old proof should NOT validate against new root (tree changed)
        valid_new = SparseMerkleTree.verify_inclusion(
            b"alice", b"alice_key_value_placeholder_32b!", proof_alice, root_after
        )
        assert valid_new is False

    def test_all_entries_verify(self):
        """Every inserted entry should produce a valid inclusion proof."""
        tree = SparseMerkleTree()
        entries = {f"user_{i}".encode(): f"key_{i}_value_padded_to_32_bytes_".encode()
                   for i in range(20)}
        for k, v in entries.items():
            tree.insert(k, v)

        for k, v in entries.items():
            proof = tree.prove(k)
            assert SparseMerkleTree.verify_inclusion(k, v, proof, tree.root), \
                f"Failed for key {k}"


# ── Non-inclusion proofs ──────────────────────────────────────────────────────

class TestNonInclusionProofs:

    def test_prove_absent_key_is_not_member(self, populated_tree):
        proof = populated_tree.prove(b"charlie")
        assert proof.is_member is False

    def test_non_inclusion_verify_absent_key(self, populated_tree):
        proof = populated_tree.prove(b"charlie")
        valid = SparseMerkleTree.verify_non_inclusion(
            b"charlie", proof, populated_tree.root
        )
        assert valid is True

    def test_non_inclusion_wrong_root(self, populated_tree):
        proof = populated_tree.prove(b"charlie")
        fake_root = b"\x00" * 32
        valid = SparseMerkleTree.verify_non_inclusion(
            b"charlie", proof, fake_root
        )
        assert valid is False

    def test_member_fails_non_inclusion(self, populated_tree):
        """
        A key that IS in the tree should fail non-inclusion verification.
        This is the MITM detection mechanism:
          if attacker substitutes a key, the proof was generated for the
          real key, not the fake one. The fake key has no valid inclusion
          proof, and the real position is not empty (non-inclusion also fails).
        """
        proof = populated_tree.prove(b"alice")
        # alice IS in the tree, so non-inclusion should fail
        valid = SparseMerkleTree.verify_non_inclusion(
            b"alice", proof, populated_tree.root
        )
        assert valid is False

    def test_non_inclusion_empty_tree(self, tree):
        """Any key is absent from an empty tree."""
        proof = tree.prove(b"anyone")
        valid = SparseMerkleTree.verify_non_inclusion(
            b"anyone", proof, tree.root
        )
        assert valid is True

    def test_non_inclusion_after_delete(self, tree):
        """After deleting a key, non-inclusion proof should succeed."""
        tree.insert(b"temp_key", b"temp_value_32_bytes_placeholder!")
        tree.delete(b"temp_key")
        proof = tree.prove(b"temp_key")
        valid = SparseMerkleTree.verify_non_inclusion(
            b"temp_key", proof, tree.root
        )
        assert valid is True


# ── MITM detection specific tests ────────────────────────────────────────────

class TestMITMDetection:

    def test_substituted_key_fails_inclusion(self, tree):
        """
        Core MITM detection test.
        Alice registers key K1. Attacker substitutes K2.
        Bob tries to verify K2 with Alice's proof → should FAIL.
        """
        real_key   = b"real_ephemeral_key_32_bytes_data"
        forged_key = b"forged_key_from_attacker_32bytes"

        tree.insert(b"alice_ek", real_key)
        root = tree.root

        # Generate proof for the REAL key
        proof = tree.prove(b"alice_ek")

        # Bob receives the FORGED key and tries to verify
        mitm_detected = not SparseMerkleTree.verify_inclusion(
            b"alice_ek", forged_key, proof, root
        )
        assert mitm_detected is True, "MITM should have been detected"

    def test_real_key_passes_inclusion(self, tree):
        """The real key should always pass verification."""
        real_key = b"real_ephemeral_key_32_bytes_data"
        tree.insert(b"alice_ek", real_key)
        root = tree.root
        proof = tree.prove(b"alice_ek")

        verified = SparseMerkleTree.verify_inclusion(
            b"alice_ek", real_key, proof, root
        )
        assert verified is True

    def test_proof_size_constant(self, tree):
        """
        Proof size must always be DEPTH = 256, regardless of tree size.
        This is why SMT was chosen over CONIKS VRF Prefix Tree.
        """
        for count in [1, 5, 50, 100]:
            t = SparseMerkleTree()
            for i in range(count):
                t.insert(f"key{i}".encode(), f"val{i}_padded_to_32_bytes_______".encode())
            proof = t.prove(b"key0")
            assert len(proof.siblings) == DEPTH, \
                f"Proof size {len(proof.siblings)} ≠ {DEPTH} for tree of {count} entries"


# ── Empty hash pre-computation ────────────────────────────────────────────────

class TestEmptyHashes:

    def test_empty_hash_chain_length(self):
        assert len(EMPTY) == DEPTH + 1

    def test_empty_hashes_are_all_bytes32(self):
        for h in EMPTY:
            assert isinstance(h, bytes) and len(h) == 32

    def test_empty_hashes_are_distinct(self):
        """Each level should have a unique empty hash."""
        assert len(set(EMPTY)) == len(EMPTY)

    def test_empty_tree_root_equals_empty_depth(self):
        tree = SparseMerkleTree()
        assert tree.root == EMPTY[DEPTH]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
