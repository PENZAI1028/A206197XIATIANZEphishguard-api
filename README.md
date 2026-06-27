# PhishGuard

PhishGuard is a user-triggered, explainable phishing URL analysis system.
This repository contains the complete frontend, Flask API, trained models,
evaluation code, and the training dataset used by the project.

## Repository structure

- `front/`: Vite and React frontend. Production output is written to `front/dist/`.
- `phishguard/backend/`: Flask API, scoring rules, model files, tests, and training scripts.
- `phishguard/dataset/`: Model training datasets.
- `render.yaml`: Render Blueprint for the frontend static site and backend API.

## Local development

Frontend:

```bash
cd front
npm ci
npm run dev
```

Backend:

```bash
cd phishguard/backend
pip install -r requirements.txt
python app.py
```

## Production

Render builds both services from this monorepo:

- Frontend root directory: `front`
- Backend root directory: `phishguard/backend`

