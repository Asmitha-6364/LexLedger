import time
import json
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

class Block:
    def __init__(self, clause_hash, prev_hash, signatures, timestamp=None, public_keys=None):
        self.clause_hash = clause_hash
        self.prev_hash = prev_hash
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.signatures = signatures  # dict: party_name -> signature_str (base64)
        self.public_keys = public_keys or {}  # dict: party_name -> public_key_pem (string)
        self.block_hash = self.compute_hash()

    def get_signing_data(self) -> bytes:
        """Returns the canonical bytes to be signed by the parties."""
        data = {
            "clause_hash": self.clause_hash,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def compute_hash(self) -> str:
        """Computes the hash of the entire block including signatures."""
        data = {
            "clause_hash": self.clause_hash,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "signatures": self.signatures,
            "public_keys": self.public_keys
        }
        serialized = json.dumps(data, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def verify_signatures(self) -> bool:
        """Verifies that signatures from both parties are present and valid."""
        signing_data = self.get_signing_data()
        
        # Validate that signatures dictionary has at least 2 entries (both parties)
        if not self.signatures or len(self.signatures) < 2:
            return False
            
        for party, sig_b64 in self.signatures.items():
            if party not in self.public_keys:
                return False
            try:
                public_key_pem = self.public_keys[party].encode("utf-8")
                public_key = serialization.load_pem_public_key(public_key_pem)
                signature = base64.b64decode(sig_b64)
                public_key.verify(
                    signature,
                    signing_data,
                    ec.ECDSA(hashes.SHA256())
                )
            except Exception:
                return False
        return True


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        # Genesis block has placeholder values and timestamp 0
        genesis = Block(
            clause_hash="genesis_clause_hash",
            prev_hash="0",
            signatures={},
            timestamp=0.0
        )
        self.chain.append(genesis)

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, block: Block) -> None:
        """Adds a block to the chain."""
        self.chain.append(block)

    def validate_chain(self) -> bool:
        """Validates the entire chain for hash integrity and signatures."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]

            # 1. Verify block's own hash hasn't changed
            if current.block_hash != current.compute_hash():
                print(f"Validation Error: Block {i} hash has been tampered with.")
                return False

            # 2. Verify chaining (prev_hash links correctly)
            if current.prev_hash != prev.block_hash:
                print(f"Validation Error: Block {i} prev_hash links incorrectly.")
                return False

            # 3. Verify signatures on the block from both parties
            if not current.verify_signatures():
                print(f"Validation Error: Block {i} signatures are invalid or incomplete.")
                return False

        return True


def generate_ecdsa_key_pair():
    """Generates a new ECDSA SECP256R1 private/public key pair (PEM string format)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return pem_private, pem_public


def sign_data(private_key_pem: str, data: bytes) -> str:
    """Signs bytes using the private key and returns base64 string."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode("utf-8")
