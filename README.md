# armor-multi-agents

## creat .venv
py -3.11 -m venv .venv OR py -3.12 -m venv .venv 2>&1
.venv\Scripts\activate

## upgrade pip
python.exe -m pip install --upgrade pip

## install requirements
pip install -r backend\requirements.txt

## train model (once)
python -m backend.agents.aca_trainer   # only needed once — trains and saves backend/models/aca_model.pkl

## run backend
uvicorn server:app --port 8000
