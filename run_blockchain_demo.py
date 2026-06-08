import copy
from blockchain import Blockchain, Block, generate_ecdsa_key_pair, sign_data

def run_demo():
    print("=============================================================")
    print("Starting Build 6: Simple Blockchain from Scratch Demonstration")
    print("=============================================================\n")

    # 1. Generate keys for Party A and Party B
    print("[1] Generating ECDSA SECP256R1 key pairs for Party A and Party B...")
    priv_a, pub_a = generate_ecdsa_key_pair()
    priv_b, pub_b = generate_ecdsa_key_pair()
    print("  - Party A Public Key:")
    print("    " + pub_a.split('\n')[1]) # print just the first line of base64
    print("  - Party B Public Key:")
    print("    " + pub_b.split('\n')[1])
    print("[OK] Key pairs generated successfully.\n")

    # 2. Initialize Blockchain
    print("[2] Initializing the blockchain...")
    blockchain = Blockchain()
    print(f"  - Genesis block hash: {blockchain.chain[0].block_hash}")
    print("[OK] Blockchain initialized.\n")

    # 3. Add signed blocks representing contract clauses
    clauses_to_add = [
        ("8a6eb810f8a86fb80f12dafe73ac2e0ca6daf3bb7d82bb5a69ddab28d45132a2", "clause_1_payment_terms"),
        ("852dba3cfc9642cb5dd3471408f211b2db55667733f59c6e9ca508e4b214f5df", "clause_2_termination"),
        ("6c823b1cfef8836a7e3bfd72d0155d8b9e2183585af01f6e4ac275c2e893ab6e", "clause_3_liability")
    ]

    print("[3] Adding and signing blocks for contract clauses...")
    for clause_hash, clause_id in clauses_to_add:
        prev_block = blockchain.get_latest_block()
        
        # Create a block placeholder to generate the canonical signing data
        temp_block = Block(
            clause_hash=clause_hash,
            prev_hash=prev_block.block_hash,
            signatures={},
            public_keys={"party_a": pub_a, "party_b": pub_b}
        )
        
        signing_data = temp_block.get_signing_data()
        
        # Sign with both parties' private keys
        sig_a = sign_data(priv_a, signing_data)
        sig_b = sign_data(priv_b, signing_data)
        
        # Create the final block containing the signatures
        signed_block = Block(
            clause_hash=clause_hash,
            prev_hash=prev_block.block_hash,
            signatures={"party_a": sig_a, "party_b": sig_b},
            timestamp=temp_block.timestamp,
            public_keys={"party_a": pub_a, "party_b": pub_b}
        )
        
        blockchain.add_block(signed_block)
        print(f"  - Added block for '{clause_id}':")
        print(f"    * Block Hash: {signed_block.block_hash}")
        print(f"    * Link (prev_hash): {signed_block.prev_hash}")
        print("    * Status: Signed by both Party A and Party B.")

    print("\n[4] Validating the intact chain...")
    is_valid = blockchain.validate_chain()
    print(f"  - Chain validation status: {is_valid}")
    assert is_valid == True, "Validation of an intact chain should succeed!"
    print("[OK] Intact chain validated successfully!\n")

    # 5. Tampering Scenarios
    print("[5] Simulating tampering scenarios...")

    # Scenario A: Modify a clause hash
    print("\n  Scenario A: Tampering with a block's clause hash...")
    tampered_blockchain = copy.deepcopy(blockchain)
    # Modify block 2's clause_hash
    tampered_blockchain.chain[2].clause_hash = "8888888888888888888888888888888888888888888888888888888888888888"
    print("    * Altered block 2 clause_hash to custom invalid hash.")
    is_valid = tampered_blockchain.validate_chain()
    print(f"    * Validation status: {is_valid}")
    assert is_valid == False, "Tampering with clause hash must fail chain validation!"
    print("    * Result: [PASS] Tamper successfully detected (validation failed).")

    # Scenario B: Tamper with previous hash linking (chaining)
    print("\n  Scenario B: Tampering with block chaining link (prev_hash)...")
    tampered_blockchain = copy.deepcopy(blockchain)
    # Modify block 3's prev_hash to break connection to block 2
    tampered_blockchain.chain[3].prev_hash = "broken_link_hash"
    print("    * Altered block 3 prev_hash to random string.")
    is_valid = tampered_blockchain.validate_chain()
    print(f"    * Validation status: {is_valid}")
    assert is_valid == False, "Tampering with chaining links must fail chain validation!"
    print("    * Result: [PASS] Tamper successfully detected (validation failed).")

    # Scenario C: Tamper with a digital signature (forgery)
    print("\n  Scenario C: Tampering with digital signatures...")
    tampered_blockchain = copy.deepcopy(blockchain)
    # Replace party_a's signature in block 1 with party_a's signature from block 2
    tampered_blockchain.chain[1].signatures["party_a"] = tampered_blockchain.chain[2].signatures["party_a"]
    print("    * Copied Party A signature from Block 2 to Block 1.")
    is_valid = tampered_blockchain.validate_chain()
    print(f"    * Validation status: {is_valid}")
    assert is_valid == False, "Forged signature must fail chain validation!"
    print("    * Result: [PASS] Tamper successfully detected (validation failed).")

    # Scenario D: Remove a party's signature (incomplete signatures)
    print("\n  Scenario D: Removing one of the party's signatures...")
    tampered_blockchain = copy.deepcopy(blockchain)
    # Delete party_b's signature in block 1
    del tampered_blockchain.chain[1].signatures["party_b"]
    print("    * Deleted Party B signature from Block 1.")
    is_valid = tampered_blockchain.validate_chain()
    print(f"    * Validation status: {is_valid}")
    assert is_valid == False, "Incomplete signatures must fail chain validation!"
    print("    * Result: [PASS] Tamper successfully detected (validation failed).")

    # Scenario E: Recompute block hash after modifying clause hash (chain propagation failure)
    print("\n  Scenario E: Tampering with clause hash AND recomputing that block's hash...")
    tampered_blockchain = copy.deepcopy(blockchain)
    tampered_blockchain.chain[2].clause_hash = "8888888888888888888888888888888888888888888888888888888888888888"
    tampered_blockchain.chain[2].block_hash = tampered_blockchain.chain[2].compute_hash()
    print("    * Altered block 2 clause_hash AND recomputed block 2's block_hash (bypassing block 2 direct check).")
    is_valid = tampered_blockchain.validate_chain()
    print(f"    * Validation status: {is_valid}")
    assert is_valid == False, "Tampering with a block's hash and recomputing it must fail chaining validation on the next block!"
    print("    * Result: [PASS] Chaining propagation tamper successfully detected (validation failed).")

    print("\n=============================================================")
    print("ALL BLOCKCHAIN DEMONSTRATIONS AND TAMPER TESTS PASSED!")
    print("=============================================================")

if __name__ == "__main__":
    run_demo()
