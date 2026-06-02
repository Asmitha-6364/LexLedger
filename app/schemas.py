from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


VoteChoice = Literal["approve", "reject"]
ProposalStatus = Literal["pending", "approved", "rejected"]


class ContractCreate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    text: str = Field(..., min_length=1)


class StandaloneProposalCreate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    label: str = Field(default="clause_1", max_length=255)
    text: str = Field(..., min_length=1)


class ClauseProposalCreate(BaseModel):
    position: int | None = Field(default=None, ge=1)
    label: str | None = Field(default=None, max_length=255)
    text: str = Field(..., min_length=1)


class VoteCreate(BaseModel):
    choice: VoteChoice


class UserRead(BaseModel):
    id: int
    name: str


class ExpertRead(UserRead):
    api_key: str


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
    choice: VoteChoice
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
