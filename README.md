# Urlora: Phishing URL Detection

Urlora is an explainable phishing URL intelligence application for the hackathon problem. The primary interface is now a React/Vite frontend with Home, URL Scanner, Result, Login/Signup, User Dashboard, and About views. The original Streamlit prototype remains in `app.py` as a Python reference implementation.

## Run the React frontend

```powershell
npm install
npm run dev
```

Open the Vite address shown in the terminal, usually `http://localhost:5173`.

The React frontend calls the FastAPI backend for predictions. The model stays on the server; the browser never receives the XGBoost artifact. Demo authentication and scan history are still stored in localStorage until Supabase Auth and the `url_scans` table are configured.

For a deployed frontend, `VITE_API_URL` must point to a reachable deployed FastAPI service. Leaving it blank or pointing it at `localhost` from Vercel cannot work because `localhost` means the visitor's own computer. The API also requires a real trained artifact at `MODEL_PATH`; the repository intentionally does not include one.

## Architecture

```text
React/Vite frontend → FastAPI /predict → shared URL feature extractor → XGBoost model
                                             └→ optional Supabase url_scans insert
```

The existing root-level React files are retained to avoid an unnecessary frontend rewrite. The backend follows the requested structure under `backend/`:

```text
backend/
├── main.py
├── requirements.txt
├── supabase_service.py
├── ml/
│   ├── feature_extractor.py
│   ├── train_model.py
│   ├── predict.py
│   └── model/
└── tests/
```

## Dataset status

There is currently no standalone labeled phishing URL dataset in this repository. The legacy `app.py` contains a small in-code demonstration list, but it is not used to train this XGBoost model. Provide a suitable CSV before running training; do not commit a large or sensitive dataset.

The training script detects common URL and target columns rather than assuming exact names. It accepts URL columns such as `url`, `link`, `website`, or `address`; target columns such as `label`, `type`, `class`, `status`, `result`, or `is_phishing`; and labels such as `phishing`/`legitimate`, `malicious`/`benign`, or `1`/`0`.

## XGBoost model features

`backend/ml/feature_extractor.py` is used by both training and prediction. It extracts URL length, hostname/path length, dots, hyphens, underscores, digits, special characters, subdirectories, query parameters, fragments, subdomains, HTTPS, IP host, `@`, suspicious symbols, URL shorteners, suspicious keyword count, digit ratio, and special-character ratio.

## Train and evaluate

From the repository root, after placing a labeled dataset at a local path:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
python -m backend.ml.train_model .\path\to\labeled_urls.csv
```

The script removes invalid rows, deduplicates URLs, uses a stratified holdout split, applies class weighting, trains XGBoost with a Random Forest baseline, and prints Accuracy, Precision, Recall, F1, ROC-AUC, a confusion matrix, and the classification report. It writes the model to `backend/ml/model/phishing_xgboost.pkl` and metrics to `backend/ml/model/evaluation.json`.

The model artifact is intentionally absent until a real dataset is supplied and training succeeds.

## Start the FastAPI backend

```powershell
uvicorn backend.main:app --reload --port 8000
```

Endpoints:

- `GET /health` reports API status and whether the model artifact exists.
- `POST /predict` accepts `{ "url": "https://example.com" }` and returns `prediction`, `confidence`, `risk_score`, `reasons`, and extracted features.

Until the artifact exists, `/predict` returns HTTP 503 with instructions to train the model. Invalid, empty, non-HTTP(S), whitespace-containing, or overlong URLs return a validation error. Urlora never visits or downloads from a submitted URL.

## Supabase

Create a `url_scans` table with `id`, `user_id`, `url`, `prediction`, `confidence`, `risk_score`, and `created_at`. Configure these backend-only variables in a deployment environment, never in the React bundle:

```text
SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=
SUPABASE_TABLE=url_scans
```

The service-role key is read only by `backend/supabase_service.py`. If Supabase is not configured, predictions still work and the optional persistence step is skipped. The current API deliberately stores `user_id` as null; do not reintroduce a client-supplied user-id header. Wire Supabase Auth JWT verification first, then pass the verified subject to persistence.

## Deployment

The frontend can be deployed to Vercel or Netlify with `npm run build`, using `VITE_API_URL` to point to the deployed FastAPI service. Deploy the backend separately to Render, Railway, Fly.io, or another Python host with `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`, and configure `CORS_ORIGINS`, `MODEL_PATH`, and Supabase variables there. A live deployment cannot be completed from this repository alone without a supplied dataset/model and hosting credentials.

## Testing

Feature extraction tests cover a legitimate HTTPS URL, IP/keyword phishing indicators, invalid URLs, long URLs, and special characters:

```powershell
pytest backend/tests
```

The browser build can be checked with:

```powershell
npm run build
```

The app extracts lexical features from URLs, compares Logistic Regression, Decision Tree, and Random Forest models, displays a Random Forest confusion matrix, and provides a live Safe / Phishing inspection flow. Urlora does not open the URL entered by a user.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Open the local Streamlit address shown in the terminal.

## Use a real dataset

Use the CSV uploader in the left sidebar. The app accepts common column names such as:

- URL column: `URL`, `url`, `Link`, `Website`, or `Address`
- Label column: `Label`, `label`, `Type`, `Class`, `Status`, or `Result`

Labels can be `phishing` / `legitimate`, `malicious` / `benign`, `bad` / `good`, or `1` / `0`. The app assumes `1` means phishing and `0` means legitimate.

## Legacy Streamlit reference

`app.py` remains available for the original Streamlit prototype and its model-comparison demo. It is not the production API used by the React frontend.

## Urlora product views

The Streamlit app now includes:

- Home page with the detector overview, dataset upload, model comparison, and confusion matrix
- URL Scanner page with a dedicated inspection workflow
- Result page with verdict, risk meter, signals, and extracted features
- Login / Signup demo flow using session-based authentication
- User Dashboard with session scan history, statistics, and CSV export
- About / How it works page explaining the feature pipeline and product boundaries

The React demo account is intentionally not authentication: it accepts any password and stores only a profile in localStorage. Add Supabase Auth, pass a verified Supabase user ID from a server-validated token, and add authenticated read policies before using account history in production.
