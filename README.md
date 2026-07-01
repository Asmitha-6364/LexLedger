# LexLedger

Simple contract proposal, encrypted voting, storage, and verification API.

## Run PostgreSQL

Create a local `.env` from `.env.example` and replace the placeholder secrets,
then start the local services:

```powershell
docker compose up -d
```

The API reads service credentials from `.env` / environment variables. For
local development, `DATABASE_URL`, `REDIS_URL`, and `RABBITMQ_URL` should match
the credentials used by Docker Compose.

If `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, or `RABBITMQ_DEFAULT_PASS` are missing,
the app warns and only falls back to insecure local-development defaults where a
fallback exists.

## Run the API

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open the interactive docs at http://127.0.0.1:8000/docs.

## Try It

On startup the API creates three simulated expert users:

```text
expert-alice: lexledger-expert-alice-key
expert-bob:   lexledger-expert-bob-key
expert-carol: lexledger-expert-carol-key
```

The approval threshold is 70% of active experts. With three experts, all three
must approve before a proposed clause is stored and hashed.

Build 5 stores votes as signed ElGamal ciphertexts. Individual vote choices are
not stored or returned. The API multiplies ciphertexts to produce an encrypted
tally, then decrypts only the final approval count.

Create a single-clause proposal:

```powershell
curl.exe -X POST http://127.0.0.1:8000/proposal `
  -H "Content-Type: application/json" `
  -H "X-API-Key: lexledger-expert-alice-key" `
  -d "{\"title\":\"Demo proposal\",\"label\":\"payment_terms\",\"text\":\"The buyer shall pay within 30 days.\"}"
```

Inspect the election public key:

```powershell
curl.exe http://127.0.0.1:8000/crypto/public-key
```

Draft and submit an encrypted vote as each expert. The `/vote/draft` endpoint is
a demo client helper that returns the signed encrypted payload; `/vote` only
accepts ciphertext plus signature.

```powershell
$aliceVote = curl.exe -s -X POST http://127.0.0.1:8000/proposal/1/vote/draft `
  -H "Content-Type: application/json" `
  -H "X-API-Key: lexledger-expert-alice-key" `
  -d "{\"choice\":\"approve\"}"
curl.exe -X POST http://127.0.0.1:8000/proposal/1/vote `
  -H "Content-Type: application/json" `
  -H "X-API-Key: lexledger-expert-alice-key" `
  -d $aliceVote

$bobVote = curl.exe -s -X POST http://127.0.0.1:8000/proposal/1/vote/draft `
  -H "Content-Type: application/json" `
  -H "X-API-Key: lexledger-expert-bob-key" `
  -d "{\"choice\":\"approve\"}"
curl.exe -X POST http://127.0.0.1:8000/proposal/1/vote `
  -H "Content-Type: application/json" `
  -H "X-API-Key: lexledger-expert-bob-key" `
  -d $bobVote

$carolVote = curl.exe -s -X POST http://127.0.0.1:8000/proposal/1/vote/draft `
  -H "Content-Type: application/json" `
  -H "X-API-Key: lexledger-expert-carol-key" `
  -d "{\"choice\":\"approve\"}"
curl.exe -X POST http://127.0.0.1:8000/proposal/1/vote `
  -H "Content-Type: application/json" `
  -H "X-API-Key: lexledger-expert-carol-key" `
  -d $carolVote
```

Fetch the approved proposal. It will include `status: "approved"` and a
`stored_clause_id`. Its `votes` array contains ciphertext and signature data,
not plain choices:

```powershell
curl.exe http://127.0.0.1:8000/proposal/1 `
  -H "X-API-Key: lexledger-expert-alice-key"
```

Fetch and verify the stored clause:

```powershell
curl.exe http://127.0.0.1:8000/clause/1 `
  -H "X-API-Key: lexledger-expert-alice-key"
```

Create a full contract. Its clauses become pending proposals first; they are not
stored in the `clauses` table until voting approves them:

```powershell
curl.exe -X POST http://127.0.0.1:8000/contract `
  -H "Content-Type: application/json" `
  -H "X-API-Key: lexledger-expert-alice-key" `
  -d "{\"title\":\"Demo contract\",\"text\":\"1. Payment Terms`nThe buyer shall pay within 30 days.`n`n2. Termination`nEither party may terminate with written notice.\"}"
```

Fetch a full contract, including both stored clauses and proposals:

```powershell
curl.exe http://127.0.0.1:8000/contract/1 `
  -H "X-API-Key: lexledger-expert-alice-key"
```

List all proposals, or only pending proposals:

```powershell
curl.exe http://127.0.0.1:8000/proposals `
  -H "X-API-Key: lexledger-expert-alice-key"
curl.exe "http://127.0.0.1:8000/proposals?status=pending" `
  -H "X-API-Key: lexledger-expert-alice-key"
```

To test tamper detection, edit a clause's `text` value directly in PostgreSQL,
then call `GET /contract/{id}` or `GET /clause/{id}` again. The response will
show `verified: false` for the modified clause.

`GET /experts` requires `X-API-Key` and returns expert names, organizations, and
signing public keys, but it does not return API keys. Nomination responses return
the newly generated API key once so the caller can hand it to that expert.
