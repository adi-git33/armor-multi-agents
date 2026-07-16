# armor-multi-agents

Multi-agent cyber-defense system: five cooperating agents (TMA → ACA → TIA → RCA → RAA)
detect, classify, and respond to simulated network attacks over a FIPA-ACL message bus,
with a live React dashboard and an SRS/SDD validation suite.
Architecture details: [`backend/SYSTEM.md`](backend/SYSTEM.md).

## Run with Docker (recommended)

```bash
docker compose up --build
```

- Dashboard: http://localhost:3000
- Backend API/WS: http://localhost:8000

## Run locally

### 1. Create a virtualenv

**Windows**
```bat
py -3.12 -m venv .venv
.venv\Scripts\activate
```

**macOS / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
```

### 3. Train the ML classifier (once)

```bash
python -m backend.agents.aca_trainer   # saves backend/models/aca_model.pkl
```

### 4. Run the backend

```bash
cd backend
uvicorn server:app --port 8000
```

### 5. Run the frontend (dev mode)

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

## Validation suite

```bash
cd backend
python validation/run_validation.py            # everything + chart export
python validation/run_validation.py --quick    # fast subset
python validation/run_validation.py --suite stress   # one suite (tma|aca|rca|tia|raa|system|stress|s1..s6)
```
