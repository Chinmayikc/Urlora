# Urlora: Phishing URL Detection

Urlora is an explainable phishing URL intelligence application for the hackathon problem. The primary interface is now a React/Vite frontend with Home, URL Scanner, Result, Login/Signup, User Dashboard, and About views. The original Streamlit prototype remains in `app.py` as a Python reference implementation.

## Run the React frontend

```powershell
npm install
npm run dev
```

Open the Vite address shown in the terminal, usually `http://localhost:5173`.

The React demo performs lexical URL analysis in the browser and stores demo authentication and scan history in localStorage. Connect `VITE_API_URL` from `.env` to a production API when the trained model service is ready.

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

## Features

- URL length
- Number of dots, hyphens, slashes, digits, and query characters
- Presence of `@`
- HTTPS usage
- IP address host
- Suspicious credential and payment keywords
- Hostname and path length

The supplied in-app dataset is only for a runnable demonstration. For the final judging run, upload the labelled Kaggle or UCI dataset and capture the resulting comparison table and confusion matrix.

## Urlora product views

The Streamlit app now includes:

- Home page with the detector overview, dataset upload, model comparison, and confusion matrix
- URL Scanner page with a dedicated inspection workflow
- Result page with verdict, risk meter, signals, and extracted features
- Login / Signup demo flow using session-based authentication
- User Dashboard with session scan history, statistics, and CSV export
- About / How it works page explaining the feature pipeline and product boundaries

Authentication and scan history currently live in Streamlit session state. Add a database, password hashing, and persistent user storage before using these flows in production.
