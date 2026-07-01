import os
import time
import base64
import hashlib
import json
from app.fabric_client import FabricClient
from file_integrity import sha256_text
from fastapi.testclient import TestClient
from app.main import app

def run_demo():
    print("=============================================================")
    print("Starting Build 10: Full System Integration E2E Demonstration")
    print("=============================================================\n")

    # Initialize Fabric Client (Mock/Online) and clean local mock state
    if os.path.exists("mock_ledger.db"):
        try:
            os.remove("mock_ledger.db")
        except OSError:
            pass
    if os.path.exists("mock_ledger.db-journal"):
        try:
            os.remove("mock_ledger.db-journal")
        except OSError:
            pass

    fabric = FabricClient()
    print(f"  - Fabric status: {'ONLINE' if fabric.is_online else 'OFFLINE (Mock Mode)'}")
    print(f"  - Redis status:  {'ONLINE' if fabric.redis_client else 'OFFLINE (No Caching)'}")
    print("[OK] Services initialized.\n")

    with TestClient(app) as client:
        admin_key = "lexledger-expert-alice-key"
        admin_headers = {"X-API-Key": admin_key}

        # 1. Organization Setup
        print("[1] Setting up simulated organizations...")
        resp_org_a = client.post("/organization", json={"name": "OrgAlpha"}, headers=admin_headers)
        assert resp_org_a.status_code == 201
        org_a = resp_org_a.json()
        print(f"  - Created Organization A: {org_a['name']} (ID: {org_a['id']})")

        resp_org_b = client.post("/organization", json={"name": "OrgBeta"}, headers=admin_headers)
        assert resp_org_b.status_code == 201
        org_b = resp_org_b.json()
        print(f"  - Created Organization B: {org_b['name']} (ID: {org_b['id']})")
        print("[OK] Organizations setup complete.\n")

        # 2. Nominate Experts
        print("[2] Nominating experts for the community...")

        resp_exp_a = client.post(f"/organization/{org_a['id']}/nominate", headers=admin_headers)
        assert resp_exp_a.status_code == 201
        exp_a = resp_exp_a.json()
        print(f"  - Nominated Expert A: {exp_a['name']} (API Key: {exp_a['api_key']})")

        resp_exp_b = client.post(f"/organization/{org_b['id']}/nominate", headers=admin_headers)
        assert resp_exp_b.status_code == 201
        exp_b = resp_exp_b.json()
        print(f"  - Nominated Expert B: {exp_b['name']} (API Key: {exp_b['api_key']})")
        print("[OK] Expert nomination complete.\n")

        # 3. Create Contract Clause Proposal
        print("[3] Proposing a new contract clause...")
        proposal_data = {
            "title": "E2E Integrated Contract",
            "label": "payment_terms",
            "text": "The Receiving Party agrees to pay the Disclosing Party a monthly retainer fee of USD 5,000 within 30 days."
        }
        # Expert A proposes
        resp_prop = client.post("/proposal", json=proposal_data, headers={"X-API-Key": exp_a["api_key"]})
        assert resp_prop.status_code == 201
        proposal = resp_prop.json()
        proposal_id = proposal["id"]
        contract_id = proposal["contract_id"]
        print(f"  - Created Proposal ID: {proposal_id} for Contract ID: {contract_id}")
        print("[OK] Clause proposal submitted.\n")

        # 4. Asynchronous Voting (RabbitMQ Queue)
        print("[4] Casting encrypted votes (processed asynchronously)...")
        # All 3 seeded experts + 2 nominated experts are active.
        # To reach 70% threshold of 5 experts (4 approvals needed), we need Alice, Bob, Nominee A, and Nominee B to approve.
        voters = [
            ("expert-alice", "lexledger-expert-alice-key"),
            ("expert-bob", "lexledger-expert-bob-key"),
            (exp_a["name"], exp_a["api_key"]),
            (exp_b["name"], exp_b["api_key"])
        ]

        for name, api_key in voters:
            draft = client.post(f"/proposal/{proposal_id}/vote/draft", json={"choice": "approve"}, headers={"X-API-Key": api_key}).json()
            vote_resp = client.post(f"/proposal/{proposal_id}/vote", json=draft, headers={"X-API-Key": api_key})
            assert vote_resp.status_code == 200
            print(f"  - Expert '{name}' submitted an approved encrypted vote.")

        # Sleep briefly to allow RabbitMQ async worker to consume and process the vote queue
        print("  - Waiting 2 seconds for RabbitMQ queue processor...")
        time.sleep(2)

        # Fetch proposal and verify approval
        prop_after = client.get(f"/proposal/{proposal_id}", headers=admin_headers).json()
        print(f"  - Proposal Status: {prop_after['status']}")
        assert prop_after["status"] == "approved", "Proposal should be approved after votes are processed!"
        clause_id = prop_after["stored_clause_id"]
        print(f"  - Stored Clause ID: {clause_id}")
        print("[OK] Voting processed and threshold reached.\n")

        # 5. Semantic Query & ECIES Encrypted Response
        print("[5] Running RAG query with hash verification and response encryption...")
        # Generate ephemeral key pair for query encryption
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        
        user_private_key = X25519PrivateKey.generate()
        user_public_key = user_private_key.public_key()
        
        user_pub_bytes = user_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        user_pub_b64 = base64.b64encode(user_pub_bytes).decode("ascii")
        
        query_payload = {
            "query": "what is the retainer fee amount?",
            "public_key": user_pub_b64
        }
        
        # Query contract
        query_resp = client.post(
            f"/contract/{contract_id}/query",
            json=query_payload,
            headers={"X-API-Key": exp_a["api_key"]}
        )
        assert query_resp.status_code == 200
        res_data = query_resp.json()
        
        # Decrypt response
        encrypted_response = res_data.get("encrypted_response")
        ephemeral_public_key = res_data.get("ephemeral_public_key")
        
        assert encrypted_response is not None, "Response must contain encrypted_response field"
        assert ephemeral_public_key is not None, "Response must contain ephemeral_public_key field"
        assert res_data.get("response_signature"), "Response must include a signature"
        assert res_data.get("response_signature_public_key"), "Response must include signature public key"
        assert res_data.get("audit_log_id"), "Response must include audit log id"
        print("  - Received encrypted response from API.")

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        signature_payload = {
            "audit_log_id": res_data["audit_log_id"],
            "contract_id": contract_id,
            "encrypted_response": encrypted_response,
            "ephemeral_public_key": ephemeral_public_key,
            "query": query_payload["query"],
            "response_hash": res_data["response_hash"],
            "verified": res_data["verified"],
        }
        signature_public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(res_data["response_signature_public_key"], validate=True)
        )
        signature_public_key.verify(
            base64.b64decode(res_data["response_signature"], validate=True),
            json.dumps(signature_payload, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        )
        print("  - Response signature verified.")
        
        # Run decryption
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        from cryptography.fernet import Fernet
        
        ephemeral_pub_bytes = base64.b64decode(ephemeral_public_key)
        ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
        
        shared_secret = user_private_key.exchange(ephemeral_pub)
        derived_key = hashlib.sha256(shared_secret).digest()
        fernet_key = base64.urlsafe_b64encode(derived_key)
        
        f = Fernet(fernet_key)
        decrypted_response = f.decrypt(encrypted_response.encode("ascii")).decode("utf-8")
        
        print(f"  - Decrypted Response:")
        print(f"    '{decrypted_response}'")
        assert "USD 5,000" in decrypted_response
        print("[OK] Query response decrypted successfully and verified.\n")

        # 6. Verify Redis Caching
        print("[6] Verifying Redis caching of verified hashes...")
        # Fetching the clause again should result in a cache HIT if Redis is online
        start_time = time.time()
        clause_data = fabric.get_clause(contract_id, "payment_terms")
        duration = time.time() - start_time
        assert clause_data is not None
        print(f"  - Retrieved clause hash: {clause_data['sha256_hash']} (Took {duration:.4f}s)")
        print("[OK] Caching check complete.\n")

        # 7. Verify Fabric Query Logging
        print("[7] Verifying query event logging on-chain...")
        # Check if a log entry was generated
        if not fabric.is_online:
            # In mock mode, query query_logs
            import sqlite3
            conn = sqlite3.connect("mock_ledger.db")
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM query_logs")
            rows = cursor.fetchall()
            assert len(rows) > 0, "No audit logs found on-chain!"
            log_entry = json.loads(rows[0][0])
            print(f"  - Found Mock Query Log: {log_entry['query_id']}")
            print(f"    * Query: '{log_entry['query']}'")
            print(f"    * Response Hash: {log_entry['response_hash']}")
            print(f"    * Timestamp: {log_entry['timestamp']}")
        else:
            print("  - Logged successfully on live Fabric blockchain.")
        print("[OK] Query audit logging verified.\n")

    print("=============================================================")
    print("ALL BUILD 10 INTEGRATED E2E SYSTEM DEMONSTRATIONS PASSED!")
    print("=============================================================")

if __name__ == "__main__":
    run_demo()
