from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session

from file_integrity import sha256_text, split_into_clauses

from . import models
from .database import create_db_and_tables, get_db
from .schemas import ClauseRead, ContractCreate, ContractRead


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    create_db_and_tables()
    yield


app = FastAPI(
    title="LexLedger Contract Storage API",
    version="0.1.0",
    lifespan=lifespan,
)


def build_clause_response(clause: models.Clause) -> ClauseRead:
    current_hash = sha256_text(clause.text)

    return ClauseRead(
        id=clause.id,
        contract_id=clause.contract_id,
        position=clause.position,
        label=clause.label,
        text=clause.text,
        stored_hash=clause.sha256_hash,
        current_hash=current_hash,
        verified=current_hash == clause.sha256_hash,
    )


def build_contract_response(contract: models.Contract) -> ContractRead:
    clauses = [build_clause_response(clause) for clause in contract.clauses]

    return ContractRead(
        id=contract.id,
        title=contract.title,
        text=contract.text,
        created_at=contract.created_at,
        clause_count=len(clauses),
        verified=all(clause.verified for clause in clauses),
        clauses=clauses,
    )


@app.post(
    "/contract",
    response_model=ContractRead,
    status_code=status.HTTP_201_CREATED,
)
def create_contract(payload: ContractCreate, db: Session = Depends(get_db)) -> ContractRead:
    if not payload.text.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Contract text cannot be blank.",
        )

    split_clauses = split_into_clauses(payload.text)
    if not split_clauses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No clause text found in the contract.",
        )

    contract = models.Contract(title=payload.title, text=payload.text)
    db.add(contract)
    db.flush()

    for position, (label, clause_text) in enumerate(split_clauses, start=1):
        db.add(
            models.Clause(
                contract_id=contract.id,
                position=position,
                label=label,
                text=clause_text,
                sha256_hash=sha256_text(clause_text),
            )
        )

    db.commit()
    db.refresh(contract)

    return build_contract_response(contract)


@app.get("/contract/{contract_id}", response_model=ContractRead)
def get_contract(contract_id: int, db: Session = Depends(get_db)) -> ContractRead:
    contract = db.get(models.Contract, contract_id)
    if contract is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Contract not found.",
        )

    return build_contract_response(contract)


@app.get("/clause/{clause_id}", response_model=ClauseRead)
def get_clause(clause_id: int, db: Session = Depends(get_db)) -> ClauseRead:
    clause = db.get(models.Clause, clause_id)
    if clause is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Clause not found.",
        )

    return build_clause_response(clause)
