# Procfile — used by `make up` to start every long-running Vigil
# process under one supervisor (honcho). Each line is `name: command`;
# honcho prefixes process output with the name in its log stream.
#
# Backend processes all run from `backend/`. Frontend from `frontend/`.
# The activated venv (`backend/.venv` after `make install`) is on PATH
# so `python`, `uvicorn`, `alembic`, and `npm` resolve correctly.

api:         bash -c 'cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8000'
grpc:        bash -c 'cd backend && python -m app.grpc.server'
normalizer:  bash -c 'cd backend && python -m app.workers.normalizer'
indexer:     bash -c 'cd backend && python -m app.workers.indexer'
detector:    bash -c 'cd backend && python -m app.workers.detector'
sigma:       bash -c 'cd backend && python -m app.workers.sigma_realtime'
anomaly:     bash -c 'cd backend && python -m app.workers.anomaly'
tamper:      bash -c 'cd backend && python -m app.workers.tamper'
silence:     bash -c 'cd backend && python -m app.workers.silence'
quarantine:  bash -c 'cd backend && python -m app.workers.quarantine'
sweep:       bash -c 'cd backend && python -m app.workers.sweep_scheduler'
frontend:    bash -c 'cd frontend && npm run dev -- --host 0.0.0.0'
