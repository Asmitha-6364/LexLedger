# LexLedger

Simple contract storage and verification API.

## Run PostgreSQL

```powershell
docker compose up -d
```

The default API database URL is:

```text
postgresql+psycopg://lexledger:lexledger@localhost:5432/lexledger
```

Override it with `DATABASE_URL` if needed.

## Run the API

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open the interactive docs at http://127.0.0.1:8000/docs.

## Try It

Create a contract:

```powershell
curl.exe -X POST http://127.0.0.1:8000/contract `
  -H "Content-Type: application/json" `
  -d "{\"title\":\"Demo contract\",\"text\":\"1. Payment Terms`nThe buyer shall pay within 30 days.`n`n2. Termination`nEither party may terminate with written notice.\"}"
```

Fetch and verify the full contract:

```powershell
curl.exe http://127.0.0.1:8000/contract/1
```

Fetch and verify one clause:

```powershell
curl.exe http://127.0.0.1:8000/clause/1
```

To test tamper detection, edit a clause's `text` value directly in PostgreSQL,
then call `GET /contract/{id}` or `GET /clause/{id}` again. The response will
show `verified: false` for the modified clause.
