from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ELGAMAL_PRIME = int(
    "".join(
        (
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        )
    ),
    16,
)
ELGAMAL_GENERATOR = 2
DEFAULT_ELECTION_SECRET = "lexledger-build-5-demo-election-key"


@dataclass(frozen=True)
class ElGamalPublicKey:
    p: int
    g: int
    y: int


@dataclass(frozen=True)
class ElGamalPrivateKey:
    public_key: ElGamalPublicKey
    x: int


@dataclass(frozen=True)
class ElGamalCiphertext:
    c1: int
    c2: int


def choice_to_bit(choice: str) -> int:
    if choice == "approve":
        return 1
    if choice == "reject":
        return 0
    raise ValueError("Vote choice must be 'approve' or 'reject'.")


def _derive_scalar(secret: str, label: str, modulo: int) -> int:
    digest = hashlib.sha256(f"{label}:{secret}".encode("utf-8")).digest()
    return 2 + (int.from_bytes(digest, "big") % (modulo - 3))


@lru_cache
def election_private_key() -> ElGamalPrivateKey:
    raw_private_key = os.getenv("LEXLEDGER_ELGAMAL_PRIVATE_KEY")
    if raw_private_key is not None:
        x = int(raw_private_key)
        if not 2 <= x <= ELGAMAL_PRIME - 2:
            raise ValueError("LEXLEDGER_ELGAMAL_PRIVATE_KEY is outside the group.")
    else:
        secret = os.getenv("LEXLEDGER_ELECTION_SECRET", DEFAULT_ELECTION_SECRET)
        x = _derive_scalar(secret, "elgamal-election-private-key", ELGAMAL_PRIME)

    public_key = ElGamalPublicKey(
        p=ELGAMAL_PRIME,
        g=ELGAMAL_GENERATOR,
        y=pow(ELGAMAL_GENERATOR, x, ELGAMAL_PRIME),
    )
    return ElGamalPrivateKey(public_key=public_key, x=x)


def election_public_key() -> ElGamalPublicKey:
    return election_private_key().public_key


def public_key_document(public_key: ElGamalPublicKey | None = None) -> dict[str, str]:
    key = public_key or election_public_key()
    return {
        "algorithm": "simplified-additive-elgamal",
        "p": str(key.p),
        "g": str(key.g),
        "y": str(key.y),
    }


def encrypt_vote(value: int, public_key: ElGamalPublicKey | None = None) -> ElGamalCiphertext:
    if value not in (0, 1):
        raise ValueError("Only binary votes 0 or 1 can be encrypted.")

    key = public_key or election_public_key()
    nonce = secrets.randbelow(key.p - 3) + 2
    c1 = pow(key.g, nonce, key.p)
    encoded_vote = pow(key.g, value, key.p)
    c2 = (encoded_vote * pow(key.y, nonce, key.p)) % key.p
    return ElGamalCiphertext(c1=c1, c2=c2)


def add_ciphertexts(
    ciphertexts: list[ElGamalCiphertext],
    public_key: ElGamalPublicKey | None = None,
) -> ElGamalCiphertext:
    key = public_key or election_public_key()
    total_c1 = 1
    total_c2 = 1

    for ciphertext in ciphertexts:
        total_c1 = (total_c1 * ciphertext.c1) % key.p
        total_c2 = (total_c2 * ciphertext.c2) % key.p

    return ElGamalCiphertext(c1=total_c1, c2=total_c2)


def decrypt_total(
    ciphertext: ElGamalCiphertext,
    max_total: int,
    private_key: ElGamalPrivateKey | None = None,
) -> int:
    key = private_key or election_private_key()
    shared_secret = pow(ciphertext.c1, key.x, key.public_key.p)
    encoded_total = (ciphertext.c2 * pow(shared_secret, -1, key.public_key.p)) % key.public_key.p

    running_value = 1
    for total in range(max_total + 1):
        if running_value == encoded_total:
            return total
        running_value = (running_value * key.public_key.g) % key.public_key.p

    raise ValueError("Encrypted tally could not be decoded as a valid approval count.")


def ciphertext_from_decimal_strings(c1: str, c2: str) -> ElGamalCiphertext:
    try:
        parsed_c1 = int(c1)
        parsed_c2 = int(c2)
    except ValueError as exc:
        raise ValueError("Ciphertext values must be decimal integers.") from exc

    key = election_public_key()
    if not 1 <= parsed_c1 < key.p or not 1 <= parsed_c2 < key.p:
        raise ValueError("Ciphertext values are outside the election group.")

    return ElGamalCiphertext(c1=parsed_c1, c2=parsed_c2)


def ciphertext_to_document(ciphertext: ElGamalCiphertext) -> dict[str, str]:
    return {"c1": str(ciphertext.c1), "c2": str(ciphertext.c2)}


def simulated_expert_private_key(api_key: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"lexledger-signing-key:{api_key}".encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def signing_public_key_for_api_key(api_key: str) -> str:
    return signing_public_key_to_text(simulated_expert_private_key(api_key).public_key())


def signing_public_key_to_text(public_key: Ed25519PublicKey) -> str:
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode("ascii")


def _signature_message(
    proposal_id: int,
    user_id: int,
    ciphertext: ElGamalCiphertext,
) -> bytes:
    message = {
        "ciphertext": ciphertext_to_document(ciphertext),
        "proposal_id": proposal_id,
        "user_id": user_id,
    }
    return json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_vote(
    proposal_id: int,
    user_id: int,
    ciphertext: ElGamalCiphertext,
    private_key: Ed25519PrivateKey,
) -> str:
    signature = private_key.sign(_signature_message(proposal_id, user_id, ciphertext))
    return base64.b64encode(signature).decode("ascii")


def verify_vote_signature(
    proposal_id: int,
    user_id: int,
    ciphertext: ElGamalCiphertext,
    signature: str,
    public_key_text: str,
) -> bool:
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
        public_key_bytes = base64.b64decode(public_key_text, validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(
            signature_bytes,
            _signature_message(proposal_id, user_id, ciphertext),
        )
    except (binascii.Error, InvalidSignature, ValueError):
        return False

    return True


def signature_digest(signature: str) -> str:
    return hashlib.sha256(signature.encode("ascii")).hexdigest()


def build_signed_encrypted_vote_payload(
    proposal_id: int,
    user_id: int,
    choice: str,
    api_key: str,
) -> dict[str, object]:
    ciphertext = encrypt_vote(choice_to_bit(choice))
    signature = sign_vote(
        proposal_id=proposal_id,
        user_id=user_id,
        ciphertext=ciphertext,
        private_key=simulated_expert_private_key(api_key),
    )
    return {
        "ciphertext": ciphertext_to_document(ciphertext),
        "signature": signature,
    }
