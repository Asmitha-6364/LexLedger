import json
import os
import subprocess
from pathlib import Path
from sqlalchemy import create_engine, text

# Set test environment database URL before importing app modules
test_db_file = Path("test_lexledger.db")
if test_db_file.exists():
    try:
        test_db_file.unlink()
    except OSError:
        pass

os.environ["DATABASE_URL"] = f"sqlite:///{test_db_file.resolve()}"

from fastapi.testclient import TestClient
from app.main import app
import file_integrity

def run_cmd(args):
    result = subprocess.run(
        [".\\.venv\\Scripts\\python.exe"] + args,
        capture_output=True,
        text=True,
        check=False
    )
    return result

def test_build_1():
    print("\n--- Verifying Build 1: Document Hasher and Tamper Detector ---")
    contract_file = Path("test_contract.txt")
    hash_file = Path("test_contract.txt.sha256")
    
    # 1. Create a contract text file
    contract_file.write_text("This is the original contract content. Agreed by all parties.", encoding="utf-8")
    
    # 2. Hash it
    result = run_cmd(["file_integrity.py", "save", str(contract_file)])
    assert result.returncode == 0, f"Hash save failed: {result.stderr}"
    assert hash_file.exists(), "Hash file not created"
    saved_hash = hash_file.read_text(encoding="utf-8").strip()
    print(f"[OK] Saved SHA-256 hash: {saved_hash}")
    
    # 3. Verify it's intact
    result = run_cmd(["file_integrity.py", "verify", str(contract_file)])
    assert result.returncode == 0, f"Verification failed: {result.stderr}"
    assert "OK: file has not been tampered with." in result.stdout
    print("[OK] Verification reports file is intact.")
    
    # 4. Tamper with it
    contract_file.write_text("This is the tampered contract content. Modifying details.", encoding="utf-8")
    
    # 5. Verify tampering is detected
    result = run_cmd(["file_integrity.py", "verify", str(contract_file)])
    assert result.returncode == 1, "Verification succeeded on tampered file!"
    assert "WARNING: file may have been tampered with." in result.stdout
    print("[OK] Tampering successfully detected!")
    
    # Clean up
    contract_file.unlink()
    hash_file.unlink()

def test_build_2():
    print("\n--- Verifying Build 2: Clause Splitter and Multi-Hash Generator ---")
    manifest_file = Path("manifest.json")
    pdf_file = Path("full_contract.pdf")
    
    # Generate manifest using PyPDF2
    result = run_cmd(["file_integrity.py", "manifest", str(pdf_file)])
    assert result.returncode == 0, f"Manifest generation failed: {result.stderr}"
    assert manifest_file.exists(), "Manifest JSON file not created"
    
    # Load manifest and verify structure
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)
        
    print(f"[OK] Manifest contains {len(manifest)} clauses:")
    for clause_id, clause_hash in manifest.items():
        print(f"  - {clause_id}: {clause_hash}")
        assert len(clause_hash) == 64, f"Invalid SHA-256 hash length for {clause_id}"
        
    assert "clause_1_payment_terms" in manifest
    assert "clause_2_termination" in manifest
    print("[OK] Build 2 Manifest verification passed.")

def test_build_3_4_5():
    print("\n--- Verifying Builds 3, 4, and 5: REST API, Voting, and Encryption ---")
    with TestClient(app) as client:
        # 1. Verify simulated experts are seeded
        response = client.get("/experts")
        assert response.status_code == 200
        experts = response.json()
        assert len(experts) == 3, f"Expected 3 experts, found {len(experts)}"
        expert_map = {e["name"]: e["api_key"] for e in experts}
        assert "expert-alice" in expert_map
        assert "expert-bob" in expert_map
        assert "expert-carol" in expert_map
        print(f"[OK] Seeded experts verified: {list(expert_map.keys())}")
        
        # 2. Check public key endpoint
        response = client.get("/crypto/public-key")
        assert response.status_code == 200
        pubkey = response.json()
        assert pubkey["algorithm"] == "simplified-additive-elgamal"
        assert "p" in pubkey and "g" in pubkey and "y" in pubkey
        print(f"[OK] ElGamal public key retrieved: algorithm={pubkey['algorithm']}")
        
        # 3. Create a proposal for a contract clause
        proposal_data = {
            "title": "Contract Proposal Demo",
            "label": "payment_terms",
            "text": "The buyer shall pay within 30 days."
        }
        response = client.post(
            "/proposal",
            json=proposal_data,
            headers={"X-API-Key": expert_map["expert-alice"]}
        )
        assert response.status_code == 201
        prop = response.json()
        proposal_id = prop["id"]
        contract_id = prop["contract_id"]
        assert prop["status"] == "pending"
        assert prop["vote_count"] == 0
        assert prop["eligible_voter_count"] == 3
        assert prop["approvals_needed"] == 3 # 70% of 3 is 3
        print(f"[OK] Proposal created: ID={proposal_id}, Status={prop['status']}")
        
        # 4. Cast votes
        # Expert Alice: Approve
        draft_resp = client.post(
            f"/proposal/{proposal_id}/vote/draft",
            json={"choice": "approve"},
            headers={"X-API-Key": expert_map["expert-alice"]}
        )
        assert draft_resp.status_code == 200
        vote_alice = draft_resp.json()
        
        vote_resp = client.post(
            f"/proposal/{proposal_id}/vote",
            json=vote_alice,
            headers={"X-API-Key": expert_map["expert-alice"]}
        )
        assert vote_resp.status_code == 200
        
        # Expert Bob: Approve
        draft_resp = client.post(
            f"/proposal/{proposal_id}/vote/draft",
            json={"choice": "approve"},
            headers={"X-API-Key": expert_map["expert-bob"]}
        )
        vote_bob = draft_resp.json()
        vote_resp = client.post(
            f"/proposal/{proposal_id}/vote",
            json=vote_bob,
            headers={"X-API-Key": expert_map["expert-bob"]}
        )
        assert vote_resp.status_code == 200
        
        # Expert Carol: Approve (triggers 3/3 votes -> status becomes approved -> stores clause)
        draft_resp = client.post(
            f"/proposal/{proposal_id}/vote/draft",
            json={"choice": "approve"},
            headers={"X-API-Key": expert_map["expert-carol"]}
        )
        vote_carol = draft_resp.json()
        vote_resp = client.post(
            f"/proposal/{proposal_id}/vote",
            json=vote_carol,
            headers={"X-API-Key": expert_map["expert-carol"]}
        )
        assert vote_resp.status_code == 200
        
        # Fetch the proposal again so that the background task has executed and updated the status
        get_resp = client.get(f"/proposal/{proposal_id}")
        assert get_resp.status_code == 200
        prop_after = get_resp.json()
        
        # Verify proposal is now approved
        assert prop_after["status"] == "approved"
        assert prop_after["stored_clause_id"] is not None
        assert prop_after["approval_count"] == 3
        print(f"[OK] Proposal approved and clause stored. Stored clause ID: {prop_after['stored_clause_id']}")
        
        # 5. Fetch and verify the stored clause
        clause_id = prop_after["stored_clause_id"]
        clause_resp = client.get(f"/clause/{clause_id}")
        assert clause_resp.status_code == 200
        clause = clause_resp.json()
        assert clause["verified"] is True
        print(f"[OK] Stored clause verified intact: {clause['verified']}, Hash: {clause['stored_hash']}")
        
        # 6. Tamper detection in the database
        print("Simulating database tampering...")
        engine = create_engine(os.environ["DATABASE_URL"])
        with engine.begin() as conn:
            # Alter the text of the stored clause directly in the DB
            conn.execute(
                text("UPDATE clauses SET text = :tampered_text WHERE id = :id"),
                {"tampered_text": "The buyer shall pay within 60 days (TAMPERED).", "id": clause_id}
            )
            
        # Query `/clause/{id}` again and check verification
        clause_resp = client.get(f"/clause/{clause_id}")
        assert clause_resp.status_code == 200
        clause = clause_resp.json()
        assert clause["verified"] is False
        print(f"[OK] Database tamper successfully detected: verified={clause['verified']}")
        print(f"     Stored Hash:  {clause['stored_hash']}")
        print(f"     Current Hash: {clause['current_hash']}")
        
        # 7. Verify Proposal Rejection
        # Create proposal 2
        proposal2_data = {
            "title": "Second Proposal",
            "label": "liability",
            "text": "The provider has zero liability."
        }
        response = client.post(
            "/proposal",
            json=proposal2_data,
            headers={"X-API-Key": expert_map["expert-alice"]}
        )
        prop2_id = response.json()["id"]
        
        # Alice: Reject
        draft_resp = client.post(
            f"/proposal/{prop2_id}/vote/draft",
            json={"choice": "reject"},
            headers={"X-API-Key": expert_map["expert-alice"]}
        )
        vote_alice = draft_resp.json()
        client.post(
            f"/proposal/{prop2_id}/vote",
            json=vote_alice,
            headers={"X-API-Key": expert_map["expert-alice"]}
        )
        
        # Bob: Reject
        draft_resp = client.post(
            f"/proposal/{prop2_id}/vote/draft",
            json={"choice": "reject"},
            headers={"X-API-Key": expert_map["expert-bob"]}
        )
        vote_bob = draft_resp.json()
        client.post(
            f"/proposal/{prop2_id}/vote",
            json=vote_bob,
            headers={"X-API-Key": expert_map["expert-bob"]}
        )
        
        # Carol: Approve
        draft_resp = client.post(
            f"/proposal/{prop2_id}/vote/draft",
            json={"choice": "approve"},
            headers={"X-API-Key": expert_map["expert-carol"]}
        )
        vote_carol = draft_resp.json()
        vote_resp = client.post(
            f"/proposal/{prop2_id}/vote",
            json=vote_carol,
            headers={"X-API-Key": expert_map["expert-carol"]}
        )
        assert vote_resp.status_code == 200
        
        # Fetch the proposal again so that the background task has executed and updated the status
        get_resp = client.get(f"/proposal/{prop2_id}")
        assert get_resp.status_code == 200
        prop2_after = get_resp.json()
        
        # Check proposal 2 status: should be rejected since only 1/3 (33%) approved, and all 3 voted.
        assert prop2_after["status"] == "rejected"
        assert prop2_after["stored_clause_id"] is None
        print(f"[OK] Rejection logic verified: Proposal status={prop2_after['status']}, Clause stored={prop2_after['stored_clause_id']}")

def test_build_6():
    print("\n--- Verifying Build 6: Simple Blockchain from Scratch ---")
    result = run_cmd(["run_blockchain_demo.py"])
    assert result.returncode == 0, f"Blockchain demo execution failed: {result.stderr}"
    print(result.stdout)
    print("[OK] Blockchain verification successfully passed all assertions.")

def test_build_7():
    print("\n--- Verifying Build 7: Basic RAG Pipeline for Contract Querying ---")
    
    # 1. Test payment terms query
    result_payment = run_cmd(["contract_query.py", "--file", "full_contract.pdf", "--query", "what are the payment terms?", "--clear"])
    assert result_payment.returncode == 0, f"Payment terms query failed: {result_payment.stderr}"
    print(result_payment.stdout)
    
    # Verify accurate answer is present
    assert "USD 5,000" in result_payment.stdout, "Payment fee not mentioned in output"
    assert "within 30 days" in result_payment.stdout or "30 days" in result_payment.stdout, "Payment timeframe not mentioned in output"
    assert "CLAUSE 1: PAYMENT TERMS" in result_payment.stdout, "Did not retrieve payment terms clause"
    print("[OK] Payment terms retrieved and answered accurately.")

    # 2. Test query not in contract
    result_dog = run_cmd(["contract_query.py", "--file", "full_contract.pdf", "--query", "what is the refund policy for dogs?"])
    # Verify fallback response is present
    assert "I cannot find the answer in the provided document." in result_dog.stdout, "Fallback message not found for unrelated query"
    print("[OK] Unrelated query handled correctly by returning fallback answer.")
    print("[OK] Build 7 RAG pipeline verification successfully passed all assertions.")


def test_build_8():
    print("\n--- Verifying Build 8: Connect Hash Verification to RAG Pipeline ---")
    with TestClient(app) as client:
        # Get experts to approve a new contract
        response = client.get("/experts")
        assert response.status_code == 200
        experts = response.json()
        expert_map = {e["name"]: e["api_key"] for e in experts}
        
        # 1. Create a contract clause proposal
        proposal_data = {
            "title": "Contract Proposal for Build 8",
            "label": "payment_terms",
            "text": "The Receiving Party agrees to pay the Disclosing Party a monthly retainer fee of USD 5,000 within 30 days."
        }
        response = client.post(
            "/proposal",
            json=proposal_data,
            headers={"X-API-Key": expert_map["expert-alice"]}
        )
        assert response.status_code == 201
        prop = response.json()
        proposal_id = prop["id"]
        
        # 2. Expert Alice: Approve
        draft_resp = client.post(
            f"/proposal/{proposal_id}/vote/draft",
            json={"choice": "approve"},
            headers={"X-API-Key": expert_map["expert-alice"]}
        )
        assert draft_resp.status_code == 200
        client.post(
            f"/proposal/{proposal_id}/vote",
            json=draft_resp.json(),
            headers={"X-API-Key": expert_map["expert-alice"]}
        )
        
        # Expert Bob: Approve
        draft_resp = client.post(
            f"/proposal/{proposal_id}/vote/draft",
            json={"choice": "approve"},
            headers={"X-API-Key": expert_map["expert-bob"]}
        )
        client.post(
            f"/proposal/{proposal_id}/vote",
            json=draft_resp.json(),
            headers={"X-API-Key": expert_map["expert-bob"]}
        )
        
        # Expert Carol: Approve (triggers 3/3 votes -> status becomes approved -> stores clause)
        draft_resp = client.post(
            f"/proposal/{proposal_id}/vote/draft",
            json={"choice": "approve"},
            headers={"X-API-Key": expert_map["expert-carol"]}
        )
        client.post(
            f"/proposal/{proposal_id}/vote",
            json=draft_resp.json(),
            headers={"X-API-Key": expert_map["expert-carol"]}
        )
        
        # Fetch proposal to ensure it is approved and clause is stored
        get_resp = client.get(f"/proposal/{proposal_id}")
        assert get_resp.status_code == 200
        prop_after = get_resp.json()
        assert prop_after["status"] == "approved"
        clause_id = prop_after["stored_clause_id"]
        assert clause_id is not None
        
        # Get the contract ID of this stored clause
        clause_resp = client.get(f"/clause/{clause_id}")
        assert clause_resp.status_code == 200
        clause = clause_resp.json()
        contract_id = clause["contract_id"]
        
        # 3. Query the contract via the API endpoint when it is intact
        query_data = {"query": "what are the payment terms?"}
        query_resp = client.post(
            f"/contract/{contract_id}/query",
            json=query_data
        )
        assert query_resp.status_code == 200
        result = query_resp.json()
        assert result["verified"] is True
        assert "USD 5,000" in result["response"]
        print("[OK] Intact contract queried successfully via API.")
        
        # 4. Query the contract via contract_query.py CLI when it is intact
        result_cli = run_cmd(["contract_query.py", "--contract-id", str(contract_id), "--query", "what are the payment terms?", "--clear"])
        assert result_cli.returncode == 0, f"CLI intact contract query failed: {result_cli.stderr}"
        assert "USD 5,000" in result_cli.stdout
        assert "VERIFICATION FAILURE" not in result_cli.stderr
        print("[OK] Intact contract queried successfully via CLI.")
        
        # 5. Tamper with the database clause text
        engine = create_engine(os.environ["DATABASE_URL"])
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE clauses SET text = :tampered_text WHERE id = :id"),
                {"tampered_text": "The Receiving Party agrees to pay the Disclosing Party a monthly retainer fee of USD 99,000 (TAMPERED) within 30 days.", "id": clause_id}
            )
        print("Simulated tampering with the database clause text.")
        
        # 6. Query the contract via the API endpoint when it is tampered
        query_resp_tampered = client.post(
            f"/contract/{contract_id}/query",
            json=query_data
        )
        assert query_resp_tampered.status_code == 400
        err_detail = query_resp_tampered.json()
        assert "Verification failed" in err_detail["detail"]
        assert "tampered with" in err_detail["detail"]
        print(f"[OK] API successfully detected tampering and returned 400 Bad Request: {err_detail['detail']}")
        
        # 7. Query the contract via CLI when it is tampered
        result_cli_tampered = run_cmd(["contract_query.py", "--contract-id", str(contract_id), "--query", "what are the payment terms?"])
        assert result_cli_tampered.returncode == 2, f"Expected exit code 2, got {result_cli_tampered.returncode}. Output: {result_cli_tampered.stdout}\nStderr: {result_cli_tampered.stderr}"
        assert "VERIFICATION FAILURE" in result_cli_tampered.stderr
        assert "tampered with in the database" in result_cli_tampered.stderr
        print("[OK] CLI successfully detected database tampering, printed verification failure, and exited with code 2.")

        # 8. Test file-based tampering detection in CLI
        contract_file = Path("temp_contract.txt")
        manifest_file = Path("temp_manifest.json")
        
        # Write temporary contract and manifest
        contract_file.write_text("CLAUSE 1: PAYMENT TERMS\nThe Receiving Party agrees to pay USD 5,000.", encoding="utf-8")
        result_manifest = run_cmd(["file_integrity.py", "manifest", str(contract_file), "-o", str(manifest_file)])
        assert result_manifest.returncode == 0
        
        # Query intact file
        result_file_ok = run_cmd(["contract_query.py", "--file", str(contract_file), "--manifest", str(manifest_file), "--query", "what are the payment terms?", "--clear"])
        assert result_file_ok.returncode == 0
        
        # Tamper with file
        contract_file.write_text("CLAUSE 1: PAYMENT TERMS\nThe Receiving Party agrees to pay USD 99,000 (TAMPERED).", encoding="utf-8")
        
        # Query tampered file
        result_file_tampered = run_cmd(["contract_query.py", "--file", str(contract_file), "--manifest", str(manifest_file), "--query", "what are the payment terms?"])
        assert result_file_tampered.returncode == 2
        assert "VERIFICATION FAILURE" in result_file_tampered.stderr
        assert "tampered with" in result_file_tampered.stderr
        print("[OK] CLI successfully detected file-based tampering and exited with code 2.")
        
        # Clean up temporary files
        if contract_file.exists():
            contract_file.unlink()
        if manifest_file.exists():
            manifest_file.unlink()


if __name__ == "__main__":
    try:
        test_build_1()
        test_build_2()
        test_build_3_4_5()
        test_build_6()
        test_build_7()
        test_build_8()
        print("\n=================================")
        print("ALL BUILDS VERIFIED SUCCESSFULLY!")
        print("=================================")
    finally:
        # Clean up database file
        if test_db_file.exists():
            try:
                test_db_file.unlink()
            except OSError:
                pass

