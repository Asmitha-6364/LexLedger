from datetime import datetime

from pydantic import BaseModel, Field


class ContractCreate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    text: str = Field(..., min_length=1)


class ClauseRead(BaseModel):
    id: int
    contract_id: int
    position: int
    label: str
    text: str
    stored_hash: str
    current_hash: str
    verified: bool


class ContractRead(BaseModel):
    id: int
    title: str | None
    text: str
    created_at: datetime
    clause_count: int
    verified: bool
    clauses: list[ClauseRead]
