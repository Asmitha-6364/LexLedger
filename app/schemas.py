from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


VoteChoice = Literal["approve", "reject"]
ProposalStatus = Literal["pending", "approved", "rejected"]


class ContractCreate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    text: str = Field(..., min_length=1, max_length=100000)


class StandaloneProposalCreate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    label: str = Field(default="clause_1", max_length=255)
    text: str = Field(..., min_length=1, max_length=50000)


class ClauseProposalCreate(BaseModel):
    position: int | None = Field(default=None, ge=1)
    label: str | None = Field(default=None, max_length=255)
    text: str = Field(..., min_length=1, max_length=50000)


class EncryptedVoteRead(BaseModel):
    c1: str
    c2: str


class VoteCreate(BaseModel):
    ciphertext: EncryptedVoteRead
    signature: str = Field(..., min_length=1)


class VoteDraftCreate(BaseModel):
    choice: VoteChoice


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class OrganizationRead(BaseModel):
    id: int
    name: str


class UserRead(BaseModel):
    id: int
    name: str


class ExpertRead(UserRead):
    signing_public_key: str | None
    organization: OrganizationRead | None = None


class ExpertCreatedRead(ExpertRead):
    api_key: str


class ElectionPublicKeyRead(BaseModel):
    algorithm: str
    p: str
    g: str
    y: str


class ClauseRead(BaseModel):
    id: int
    contract_id: int
    position: int
    label: str
    text: str
    stored_hash: str
    current_hash: str
    verified: bool


class ProposalVoteRead(BaseModel):
    id: int
    user_id: int
    user_name: str
    ciphertext: EncryptedVoteRead
    signature: str
    signature_public_key: str
    signature_digest: str
    created_at: datetime
    updated_at: datetime | None


class ProposalRead(BaseModel):
    id: int
    contract_id: int
    proposed_by: UserRead
    position: int
    label: str
    text: str
    status: ProposalStatus
    stored_clause_id: int | None
    created_at: datetime
    decided_at: datetime | None
    approval_threshold_percent: int
    eligible_voter_count: int
    approvals_needed: int
    vote_count: int
    approval_count: int
    rejection_count: int
    encrypted_approval_tally: EncryptedVoteRead | None
    votes: list[ProposalVoteRead]


class ContractRead(BaseModel):
    id: int
    title: str | None
    text: str
    created_at: datetime
    clause_count: int
    proposal_count: int
    verified: bool
    clauses: list[ClauseRead]
    proposals: list[ProposalRead]


class ContractQueryRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)
    public_key: str | None = None


class ContractQueryResponse(BaseModel):
    query: str
    response: str
    verified: bool
    retrieved_clauses: list[ClauseRead]
    encrypted_response: str | None = None
    ephemeral_public_key: str | None = None
    response_hash: str
    response_signature: str
    response_signature_public_key: str
    audit_log_id: str
