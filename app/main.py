from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from math import ceil
import os
import secrets
import time

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from sqlalchemy.orm import Session

from file_integrity import sha256_text, split_into_clauses

from . import models
from .crypto import (
    add_ciphertexts,
    build_signed_encrypted_vote_payload,
    ciphertext_from_decimal_strings,
    ciphertext_to_document,
    decrypt_total,
    election_public_key,
    public_key_document,
    response_signing_public_key_text,
    sign_response_payload,
    signature_digest,
    signing_public_key_for_api_key,
    validate_binary_vote_ciphertext,
    verify_vote_signature,
)
from .database import SessionLocal, create_db_and_tables, get_db
from .schemas import (
    ClauseProposalCreate,
    ClauseRead,
    ContractCreate,
    ContractRead,
    ElectionPublicKeyRead,
    ExpertCreatedRead,
    EncryptedVoteRead,
    ExpertRead,
    ProposalRead,
    ProposalStatus,
    ProposalVoteRead,
    StandaloneProposalCreate,
    UserRead,
    VoteCreate,
    VoteDraftCreate,
    ContractQueryRequest,
    ContractQueryResponse,
    OrganizationCreate,
    OrganizationRead,
)
from .rag import AuditLogFailedException, VerificationFailedException, run_contract_query



APPROVAL_THRESHOLD_PERCENT = 70
RATE_LIMIT_PER_MINUTE = int(os.getenv("LEXLEDGER_RATE_LIMIT_PER_MINUTE", "300"))
RATE_LIMIT_WINDOW_SECONDS = 60

PROPOSAL_PENDING = "pending"
PROPOSAL_APPROVED = "approved"
PROPOSAL_REJECTED = "rejected"

SIMULATED_EXPERTS = (
    ("expert-alice", "lexledger-expert-alice-key"),
    ("expert-bob", "lexledger-expert-bob-key"),
    ("expert-carol", "lexledger-expert-carol-key"),
)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
rate_limit_windows: dict[str, tuple[int, int]] = {}


def seed_simulated_experts() -> None:
    db = SessionLocal()
    try:
        for name, api_key in SIMULATED_EXPERTS:
            signing_public_key = signing_public_key_for_api_key(api_key)
            existing_user = (
                db.query(models.User)
                .filter(models.User.api_key == api_key)
                .one_or_none()
            )
            if existing_user is None:
                db.add(
                    models.User(
                        name=name,
                        api_key=api_key,
                        signing_public_key=signing_public_key,
                    )
                )
            elif existing_user.signing_public_key != signing_public_key:
                existing_user.signing_public_key = signing_public_key
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    create_db_and_tables()
    seed_simulated_experts()

    # Start RabbitMQ consumer if online
    from .queue_manager import is_rabbitmq_online, start_rabbitmq_consumer
    import threading
    if is_rabbitmq_online():
        t = threading.Thread(target=start_rabbitmq_consumer, daemon=True)
        t.start()

    yield


app = FastAPI(
    title="LexLedger Contract Storage API",
    version="0.2.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if RATE_LIMIT_PER_MINUTE <= 0:
        return await call_next(request)

    api_key = request.headers.get("x-api-key")
    client_host = request.client.host if request.client else "unknown"
    identity = f"api-key:{api_key}" if api_key else f"ip:{client_host}"
    now = time.monotonic()
    window = int(now // RATE_LIMIT_WINDOW_SECONDS)
    stored_window, count = rate_limit_windows.get(identity, (window, 0))

    if stored_window != window:
        stored_window = window
        count = 0

    if count >= RATE_LIMIT_PER_MINUTE:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded. Try again later."},
            headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )

    rate_limit_windows[identity] = (stored_window, count + 1)
    return await call_next(request)


@app.exception_handler(VerificationFailedException)
def verification_failed_exception_handler(request, exc: VerificationFailedException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": f"Verification failed: {exc.message}"},
    )


@app.exception_handler(AuditLogFailedException)
def audit_log_failed_exception_handler(request, exc: AuditLogFailedException):
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": f"Audit logging failed: {exc.message}"},
    )


def active_expert_count(db: Session) -> int:
    return (
        db.query(models.User)
        .filter(models.User.is_active.is_(True))
        .count()
    )


def approvals_needed(eligible_voter_count: int) -> int:
    if eligible_voter_count < 1:
        return 1

    return ceil(eligible_voter_count * APPROVAL_THRESHOLD_PERCENT / 100)


def get_current_user(
    api_key: str | None = Depends(api_key_header),
    db: Session = Depends(get_db),
) -> models.User:
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
        )

    user = (
        db.query(models.User)
        .filter(models.User.api_key == api_key, models.User.is_active.is_(True))
        .one_or_none()
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    return user


def ensure_user_signing_public_key(user: models.User, db: Session) -> str:
    if user.signing_public_key is None:
        user.signing_public_key = signing_public_key_for_api_key(user.api_key)
        db.commit()
        db.refresh(user)

    return user.signing_public_key


def build_user_response(user: models.User) -> UserRead:
    return UserRead(id=user.id, name=user.name)


def build_organization_response(org: models.Organization | None) -> OrganizationRead | None:
    if org is None:
        return None
    return OrganizationRead(id=org.id, name=org.name)


def build_expert_response(user: models.User) -> ExpertRead:
    return ExpertRead(
        id=user.id,
        name=user.name,
        signing_public_key=user.signing_public_key,
        organization=build_organization_response(user.organization),
    )


def build_created_expert_response(user: models.User) -> ExpertCreatedRead:
    return ExpertCreatedRead(
        id=user.id,
        name=user.name,
        api_key=user.api_key,
        signing_public_key=user.signing_public_key,
        organization=build_organization_response(user.organization),
    )


def build_clause_response(clause: models.Clause) -> ClauseRead:
    current_hash = sha256_text(clause.text)

    # Verify using Fabric client
    from .fabric_client import FabricClient
    client = FabricClient()
    ledger_clause = client.get_clause(clause.contract_id, clause.label)
    stored_hash = ledger_clause["sha256_hash"] if ledger_clause else clause.sha256_hash

    return ClauseRead(
        id=clause.id,
        contract_id=clause.contract_id,
        position=clause.position,
        label=clause.label,
        text=clause.text,
        stored_hash=stored_hash,
        current_hash=current_hash,
        verified=current_hash == stored_hash,
    )


def build_vote_response(vote: models.Vote) -> ProposalVoteRead:
    return ProposalVoteRead(
        id=vote.id,
        user_id=vote.user_id,
        user_name=vote.user.name,
        ciphertext=EncryptedVoteRead(
            c1=vote.ciphertext_c1,
            c2=vote.ciphertext_c2,
        ),
        signature=vote.signature,
        signature_public_key=vote.signature_public_key,
        signature_digest=vote.signature_digest,
        created_at=vote.created_at,
        updated_at=vote.updated_at,
    )


def encrypted_votes(proposal: models.Proposal) -> list[models.Vote]:
    return [
        vote
        for vote in proposal.votes
        if vote.ciphertext_c1 is not None and vote.ciphertext_c2 is not None
    ]


def encrypted_vote_tally(
    votes: list[models.Vote],
) -> tuple[int, EncryptedVoteRead | None]:
    if not votes:
        return 0, None

    ciphertexts = [
        ciphertext_from_decimal_strings(vote.ciphertext_c1, vote.ciphertext_c2)
        for vote in votes
    ]
    encrypted_tally = add_ciphertexts(ciphertexts, election_public_key())
    approval_count = decrypt_total(encrypted_tally, max_total=len(ciphertexts))
    return approval_count, EncryptedVoteRead(**ciphertext_to_document(encrypted_tally))


def build_proposal_response(proposal: models.Proposal, db: Session) -> ProposalRead:
    eligible_voters = active_expert_count(db)
    votes = encrypted_votes(proposal)
    approval_count, encrypted_approval_tally = encrypted_vote_tally(votes)
    rejection_count = len(votes) - approval_count

    return ProposalRead(
        id=proposal.id,
        contract_id=proposal.contract_id,
        proposed_by=build_user_response(proposal.proposed_by),
        position=proposal.position,
        label=proposal.label,
        text=proposal.text,
        status=proposal.status,
        stored_clause_id=proposal.stored_clause_id,
        created_at=proposal.created_at,
        decided_at=proposal.decided_at,
        approval_threshold_percent=APPROVAL_THRESHOLD_PERCENT,
        eligible_voter_count=eligible_voters,
        approvals_needed=approvals_needed(eligible_voters),
        vote_count=len(votes),
        approval_count=approval_count,
        rejection_count=rejection_count,
        encrypted_approval_tally=encrypted_approval_tally,
        votes=[build_vote_response(vote) for vote in votes],
    )


def build_contract_response(contract: models.Contract, db: Session) -> ContractRead:
    clauses = [build_clause_response(clause) for clause in contract.clauses]
    proposals = [
        build_proposal_response(proposal, db)
        for proposal in contract.proposals
    ]

    return ContractRead(
        id=contract.id,
        title=contract.title,
        text=contract.text,
        created_at=contract.created_at,
        clause_count=len(clauses),
        proposal_count=len(proposals),
        verified=bool(clauses) and all(clause.verified for clause in clauses),
        clauses=clauses,
        proposals=proposals,
    )


def ensure_text_is_not_blank(text: str, detail: str) -> str:
    cleaned_text = text.strip()
    if not cleaned_text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail,
        )

    return cleaned_text


def clean_optional_label(label: str | None, fallback: str) -> str:
    cleaned_label = (label or "").strip()
    if not cleaned_label:
        cleaned_label = fallback
    return cleaned_label[:255]


def next_contract_position(contract_id: int, db: Session) -> int:
    highest_clause_position = (
        db.query(func.max(models.Clause.position))
        .filter(models.Clause.contract_id == contract_id)
        .scalar()
        or 0
    )
    highest_proposal_position = (
        db.query(func.max(models.Proposal.position))
        .filter(models.Proposal.contract_id == contract_id)
        .scalar()
        or 0
    )

    return max(highest_clause_position, highest_proposal_position) + 1


def ensure_position_is_available(contract_id: int, position: int, db: Session) -> None:
    existing_clause = (
        db.query(models.Clause)
        .filter(
            models.Clause.contract_id == contract_id,
            models.Clause.position == position,
        )
        .one_or_none()
    )
    existing_proposal = (
        db.query(models.Proposal)
        .filter(
            models.Proposal.contract_id == contract_id,
            models.Proposal.position == position,
        )
        .one_or_none()
    )

    if existing_clause is not None or existing_proposal is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Contract already has a clause or proposal at position {position}.",
        )


def tally_proposal(proposal_id: int) -> None:
    db = SessionLocal()
    try:
        proposal = (
            db.query(models.Proposal)
            .filter(models.Proposal.id == proposal_id)
            .with_for_update()
            .one_or_none()
        )
        if proposal is None or proposal.status != PROPOSAL_PENDING:
            return

        eligible_voters = active_expert_count(db)
        needed = approvals_needed(eligible_voters)
        votes = encrypted_votes(proposal)
        approval_count, _ = encrypted_vote_tally(votes)

        if approval_count >= needed:
            clause = models.Clause(
                contract_id=proposal.contract_id,
                position=proposal.position,
                label=proposal.label,
                text=proposal.text,
                sha256_hash=sha256_text(proposal.text),
            )
            db.add(clause)
            db.flush()

            # Store in Fabric blockchain
            from .fabric_client import FabricClient
            client = FabricClient()
            client.store_clause(
                contract_id=clause.contract_id,
                position=clause.position,
                label=clause.label,
                text=clause.text,
                sha256_hash=clause.sha256_hash
            )

            proposal.status = PROPOSAL_APPROVED
            proposal.stored_clause_id = clause.id
            proposal.decided_at = datetime.now(timezone.utc)
        elif len(votes) >= eligible_voters:
            proposal.status = PROPOSAL_REJECTED
            proposal.decided_at = datetime.now(timezone.utc)

        db.commit()
    finally:
        db.close()


@app.get("/experts", response_model=list[ExpertRead])
def list_experts(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ExpertRead]:
    users = (
        db.query(models.User)
        .filter(models.User.is_active.is_(True))
        .order_by(models.User.id)
        .all()
    )

    return [build_expert_response(user) for user in users]


@app.get("/crypto/public-key", response_model=ElectionPublicKeyRead)
def get_crypto_public_key() -> ElectionPublicKeyRead:
    return ElectionPublicKeyRead(**public_key_document())


@app.post(
    "/contract",
    response_model=ContractRead,
    status_code=status.HTTP_201_CREATED,
)
def create_contract(
    payload: ContractCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ContractRead:
    contract_text = ensure_text_is_not_blank(
        payload.text,
        "Contract text cannot be blank.",
    )

    split_clauses = split_into_clauses(contract_text)
    if not split_clauses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No clause text found in the contract.",
        )

    contract = models.Contract(title=payload.title, text=contract_text)
    db.add(contract)
    db.flush()

    for position, (label, clause_text) in enumerate(split_clauses, start=1):
        db.add(
            models.Proposal(
                contract_id=contract.id,
                proposed_by_id=current_user.id,
                position=position,
                label=label,
                text=clause_text,
            )
        )

    db.commit()
    db.refresh(contract)

    return build_contract_response(contract, db)


@app.get("/contract/{contract_id}", response_model=ContractRead)
def get_contract(
    contract_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ContractRead:
    contract = db.get(models.Contract, contract_id)
    if contract is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Contract not found.",
        )

    return build_contract_response(contract, db)


@app.post(
    "/proposal",
    response_model=ProposalRead,
    status_code=status.HTTP_201_CREATED,
)
def propose_standalone_clause(
    payload: StandaloneProposalCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProposalRead:
    clause_text = ensure_text_is_not_blank(
        payload.text,
        "Clause text cannot be blank.",
    )

    contract = models.Contract(title=payload.title, text=clause_text)
    db.add(contract)
    db.flush()

    proposal = models.Proposal(
        contract_id=contract.id,
        proposed_by_id=current_user.id,
        position=1,
        label=clean_optional_label(payload.label, "clause_1"),
        text=clause_text,
    )
    db.add(proposal)
    db.commit()
    db.refresh(proposal)

    return build_proposal_response(proposal, db)


@app.post(
    "/contract/{contract_id}/proposal",
    response_model=ProposalRead,
    status_code=status.HTTP_201_CREATED,
)
def propose_contract_clause(
    contract_id: int,
    payload: ClauseProposalCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProposalRead:
    contract = db.get(models.Contract, contract_id)
    if contract is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Contract not found.",
        )

    clause_text = ensure_text_is_not_blank(
        payload.text,
        "Clause text cannot be blank.",
    )
    position = payload.position or next_contract_position(contract_id, db)
    ensure_position_is_available(contract_id, position, db)

    proposal = models.Proposal(
        contract_id=contract.id,
        proposed_by_id=current_user.id,
        position=position,
        label=clean_optional_label(payload.label, f"clause_{position}"),
        text=clause_text,
    )
    db.add(proposal)
    db.commit()
    db.refresh(proposal)

    return build_proposal_response(proposal, db)


@app.get("/proposals", response_model=list[ProposalRead])
def list_proposals(
    proposal_status: ProposalStatus | None = Query(default=None, alias="status"),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ProposalRead]:
    query = db.query(models.Proposal).order_by(models.Proposal.created_at.desc())
    if proposal_status is not None:
        query = query.filter(models.Proposal.status == proposal_status)

    return [
        build_proposal_response(proposal, db)
        for proposal in query.all()
    ]


@app.get("/proposal/{proposal_id}", response_model=ProposalRead)
def get_proposal(
    proposal_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProposalRead:
    proposal = db.get(models.Proposal, proposal_id)
    if proposal is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Proposal not found.",
        )

    return build_proposal_response(proposal, db)


@app.post("/proposal/{proposal_id}/vote/draft", response_model=VoteCreate)
def draft_encrypted_vote(
    proposal_id: int,
    payload: VoteDraftCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> VoteCreate:
    proposal = db.get(models.Proposal, proposal_id)
    if proposal is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Proposal not found.",
        )
    if proposal.status != PROPOSAL_PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Proposal is already {proposal.status}.",
        )

    ensure_user_signing_public_key(current_user, db)
    return VoteCreate(
        **build_signed_encrypted_vote_payload(
            proposal_id=proposal_id,
            user_id=current_user.id,
            choice=payload.choice,
            api_key=current_user.api_key,
        )
    )


@app.post("/proposal/{proposal_id}/vote", response_model=ProposalRead)
def vote_on_proposal(
    proposal_id: int,
    payload: VoteCreate,
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProposalRead:
    proposal = db.get(models.Proposal, proposal_id)
    if proposal is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Proposal not found.",
        )
    if proposal.status != PROPOSAL_PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Proposal is already {proposal.status}.",
        )

    try:
        ciphertext = ciphertext_from_decimal_strings(
            payload.ciphertext.c1,
            payload.ciphertext.c2,
        )
        validate_binary_vote_ciphertext(ciphertext)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    signing_public_key = ensure_user_signing_public_key(current_user, db)
    if not verify_vote_signature(
        proposal_id=proposal_id,
        user_id=current_user.id,
        ciphertext=ciphertext,
        signature=payload.signature,
        public_key_text=signing_public_key,
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Vote signature does not match the authenticated expert and ciphertext.",
        )

    signed_vote_digest = signature_digest(payload.signature)
    existing_signature = (
        db.query(models.Vote)
        .filter(
            models.Vote.proposal_id == proposal_id,
            models.Vote.signature_digest == signed_vote_digest,
        )
        .one_or_none()
    )
    if existing_signature is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate signed vote payload.",
        )

    existing_vote = (
        db.query(models.Vote)
        .filter(
            models.Vote.proposal_id == proposal_id,
            models.Vote.user_id == current_user.id,
        )
        .one_or_none()
    )
    if existing_vote is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Expert has already submitted a vote for this proposal.",
        )

    vote = models.Vote(
        proposal_id=proposal_id,
        user_id=current_user.id,
        ciphertext_c1=str(ciphertext.c1),
        ciphertext_c2=str(ciphertext.c2),
        signature=payload.signature,
        signature_public_key=signing_public_key,
        signature_digest=signed_vote_digest,
    )
    db.add(vote)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate vote payload or expert vote for this proposal.",
        ) from exc
    db.refresh(proposal)
    db.refresh(vote)

    # Publish vote event to RabbitMQ, or fallback to background_task
    from .queue_manager import is_rabbitmq_online, publish_vote
    queued = False
    if is_rabbitmq_online():
        queued = publish_vote(proposal.id, current_user.id, vote.id)
    if not queued:
        background_tasks.add_task(tally_proposal, proposal.id)

    return build_proposal_response(proposal, db)


@app.get("/clause/{clause_id}", response_model=ClauseRead)
def get_clause(
    clause_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ClauseRead:
    clause = db.get(models.Clause, clause_id)
    if clause is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Clause not found.",
        )

    return build_clause_response(clause)


@app.post(
    "/organization",
    response_model=OrganizationRead,
    status_code=status.HTTP_201_CREATED,
)
def create_organization(
    payload: OrganizationCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OrganizationRead:
    name = ensure_text_is_not_blank(
        payload.name,
        "Organization name cannot be blank.",
    )
    existing = db.query(models.Organization).filter(models.Organization.name == name).one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Organization with name {name} already exists."
        )
    org = models.Organization(name=name)
    db.add(org)
    db.commit()
    db.refresh(org)
    return OrganizationRead(id=org.id, name=org.name)


@app.post(
    "/organization/{org_id}/nominate",
    response_model=ExpertCreatedRead,
    status_code=status.HTTP_201_CREATED,
)
def nominate_expert(
    org_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExpertCreatedRead:
    org = db.get(models.Organization, org_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found."
        )
    
    # Generate a unique nominee name
    random_suffix = secrets.token_hex(4)
    nominee_name = f"nominee-{org.name}-{random_suffix}"
    api_key = f"lexledger-nominee-{random_suffix}-key"
    signing_public_key = signing_public_key_for_api_key(api_key)

    user = models.User(
        name=nominee_name,
        api_key=api_key,
        signing_public_key=signing_public_key,
        organization_id=org.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return build_created_expert_response(user)


@app.post("/contract/{contract_id}/query", response_model=ContractQueryResponse)
def query_contract(
    contract_id: int,
    payload: ContractQueryRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ContractQueryResponse:
    contract = db.get(models.Contract, contract_id)
    if contract is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Contract not found.",
        )

    try:
        response_text, retrieved_clauses_db, verified, audit_log_id, response_hash = run_contract_query(
            contract_id=contract_id,
            query=payload.query,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )

    encrypted_response = None
    ephemeral_public_key = None
    if payload.public_key:
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import serialization
            import base64
            import hashlib

            server_priv = X25519PrivateKey.generate()
            server_pub = server_priv.public_key()

            peer_pub_bytes = base64.b64decode(payload.public_key, validate=True)
            peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)

            shared_secret = server_priv.exchange(peer_pub)
            derived_key = hashlib.sha256(shared_secret).digest()
            fernet_key = base64.urlsafe_b64encode(derived_key)

            f = Fernet(fernet_key)
            encrypted_response = f.encrypt(response_text.encode("utf-8")).decode("ascii")

            server_pub_bytes = server_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            ephemeral_public_key = base64.b64encode(server_pub_bytes).decode("ascii")
            
            response_text = "[Encrypted Response]"
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to encrypt response: {e}"
            )

    signature_payload = {
        "audit_log_id": audit_log_id,
        "contract_id": contract_id,
        "encrypted_response": encrypted_response,
        "ephemeral_public_key": ephemeral_public_key,
        "query": payload.query,
        "response_hash": response_hash,
        "verified": verified,
    }

    return ContractQueryResponse(
        query=payload.query,
        response=response_text,
        verified=verified,
        retrieved_clauses=[build_clause_response(clause) for clause in retrieved_clauses_db],
        encrypted_response=encrypted_response,
        ephemeral_public_key=ephemeral_public_key,
        response_hash=response_hash,
        response_signature=sign_response_payload(signature_payload),
        response_signature_public_key=response_signing_public_key_text(),
        audit_log_id=audit_log_id,
    )
