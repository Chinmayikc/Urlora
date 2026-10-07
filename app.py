from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import ConfusionMatrixDisplay, accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier


st.set_page_config(page_title="Urlora | Phishing URL Detection", page_icon="⌁", layout="wide")

PALETTE = {
    "dark": "#07111F", "forest": "#0D2940", "olive": "#0B7285", "sage": "#23C6B8",
    "sand": "#A9D9D3", "stone": "#BFD5DE", "clay": "#F3A65A", "ochre": "#0B7285",
    "brown": "#16415B", "deep_brown": "#07111F", "paper": "#F4F9FA",
}


def load_styles() -> None:
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=IBM+Plex+Mono:wght@400;500;600&family=Source+Sans+3:wght@400;500;600;700&display=swap');
        :root {{
            --dark: {PALETTE['dark']}; --forest: {PALETTE['forest']}; --olive: {PALETTE['olive']};
            --sage: {PALETTE['sage']}; --sand: {PALETTE['sand']}; --stone: {PALETTE['stone']};
            --brown: {PALETTE['brown']}; --paper: {PALETTE['paper']}; --ink-soft: #6E4F55;
        }}
        html, body, [class*="css"] {{ font-family: 'Source Sans 3', Arial, sans-serif; color: var(--dark); }}
        .stApp {{ background: var(--paper); }}
        [data-testid="stHeader"] {{ display: none; }}
        [data-testid="stSidebar"] {{ display: none; }}
        .block-container {{ max-width: 1220px; padding: 0 3rem 4rem; }}
        .main, .main p, .main li, .main label, .main small, .main span {{ color: var(--dark); }}
        .main [data-testid="stMarkdownContainer"], .main [data-testid="stMarkdownContainer"] p,
        .main [data-testid="stMarkdownContainer"] li, .main [data-testid="stMarkdownContainer"] strong,
        .main [data-testid="stCaptionContainer"] {{ color: var(--dark) !important; }}
        .main [data-testid="stCaptionContainer"] {{ color: var(--ink-soft) !important; }}
        h1, h2, h3 {{ font-family: 'DM Serif Display', Georgia, serif !important; font-weight: 400 !important; color: var(--dark) !important; letter-spacing: -.025em; }}
        h1 {{ font-size: clamp(2.8rem, 6vw, 6.2rem) !important; line-height: .92 !important; }}
        h2 {{ font-size: 2.3rem !important; }} h3 {{ font-size: 1.5rem !important; }}
        .masthead {{ background: linear-gradient(125deg, var(--dark) 0%, var(--forest) 68%, #0B7285 100%); color: var(--paper); margin: 0 -3rem 2rem; padding: 2.2rem 3rem 2.6rem; border-bottom: 5px solid var(--sage); position: relative; overflow: hidden; }}
        .masthead::after {{ content: '⌁'; position: absolute; right: 5%; top: 7%; color: rgba(35,198,184,.2); font: 19rem/1 'DM Serif Display', Georgia, serif; transform: rotate(-13deg); }}
        .masthead * {{ color: var(--paper); }}
        .masthead-kicker, .section-kicker {{ font-family: 'IBM Plex Mono', monospace; font-size: .7rem; letter-spacing: .14em; text-transform: uppercase; }}
        .masthead-kicker {{ color: var(--sage) !important; margin-bottom: 1.25rem; }}
        .masthead-title {{ font-family: 'DM Serif Display', Georgia, serif; font-size: clamp(3rem, 7vw, 7.1rem); line-height: .86; max-width: 820px; letter-spacing: -.045em; }}
        .masthead-copy {{ max-width: 650px; color: #D4E8EA !important; font-size: 1.05rem; line-height: 1.55; margin: 1.5rem 0 2rem; position: relative; z-index: 1; }}
        .masthead-meta {{ display: flex; flex-wrap: wrap; gap: 1.5rem; border-top: 1px solid rgba(169,217,211,.35); padding-top: 1rem; font-family: 'IBM Plex Mono', monospace; font-size: .68rem; letter-spacing: .06em; text-transform: uppercase; color: #D4E8EA !important; position: relative; z-index: 1; }}
        .section-kicker {{ color: var(--olive); margin: 2.6rem 0 .7rem; }}
        .section-intro {{ color: var(--ink-soft); font-size: 1rem; line-height: 1.55; max-width: 730px; margin: 0 0 1.3rem; }}
        .control-panel {{ background: #FFF8F7; border: 1px solid var(--stone); padding: 1.2rem 1.35rem; min-height: 132px; }}
        .control-title {{ font-family: 'IBM Plex Mono', monospace; text-transform: uppercase; letter-spacing: .09em; font-size: .68rem; color: var(--olive); margin-bottom: .6rem; }}
        .data-badge {{ border: 1px solid var(--sage); padding: .35rem .55rem; color: var(--forest); font-family: 'IBM Plex Mono', monospace; font-size: .68rem; display: inline-block; line-height: 1.4; }}
        .model-status {{ font-family: 'DM Serif Display', Georgia, serif; color: var(--forest); font-size: 1.7rem; line-height: 1; margin: .35rem 0 .6rem; }}
        .model-note {{ color: var(--ink-soft); font-size: .85rem; }}
        .st-key-inspector {{ background: var(--forest); color: var(--paper); border: 1px solid var(--dark); padding: 1.5rem; box-shadow: 0 12px 30px rgba(7,17,31,.12); }}
        .st-key-inspector [data-testid="stMarkdownContainer"] *, .st-key-inspector label {{ color: var(--paper) !important; }}
        .inspector-label {{ font-family: 'IBM Plex Mono', monospace; font-size: .68rem; letter-spacing: .1em; text-transform: uppercase; color: var(--sand) !important; margin-bottom: .8rem; }}
        .stTextInput input {{ background: #FFF8F7; border: 1px solid var(--sand); border-radius: 2px; color: var(--dark); min-height: 2.8rem; }}
        .stTextInput label {{ color: var(--sand) !important; }}
        .stButton > button {{ background: var(--sage); border: 1px solid var(--sand); color: var(--dark); border-radius: 2px; font-weight: 700; min-height: 2.8rem; }}
        .stButton > button:hover {{ background: var(--sand); border-color: var(--paper); color: var(--dark); }}
        .result-panel {{ border: 1px solid var(--sage); background: #E7F5F4; padding: 1.3rem; margin-top: 1.2rem; min-height: 8rem; }}
        .result-label {{ font-family: 'IBM Plex Mono', monospace; letter-spacing: .08em; text-transform: uppercase; font-size: .68rem; color: var(--olive); margin-bottom: .5rem; }}
        .result-value {{ font-family: 'DM Serif Display', Georgia, serif; font-size: 2.45rem; line-height: 1; color: var(--forest); }}
        .result-value.danger {{ color: #C76325; }} .result-value.safe {{ color: #087F72; }}
        .risk-number {{ font-family: 'IBM Plex Mono', monospace; font-size: 1rem; color: var(--brown); margin-top: .5rem; }}
        .signal-list {{ border-left: 3px solid var(--sage); padding-left: 1rem; color: var(--ink-soft); line-height: 1.7; }}
        .rule {{ border-top: 1px solid var(--stone); margin: 2.8rem 0; }}
        .metric-line {{ border-top: 1px solid var(--stone); padding: .75rem 0; display: flex; justify-content: space-between; gap: 1rem; }}
        .metric-line:first-child {{ border-top: 0; }} .metric-name {{ color: var(--forest); }} .metric-value {{ color: var(--olive); font-family: 'IBM Plex Mono', monospace; font-size: .78rem; }}
        .feature-table {{ border-top: 2px solid var(--forest); }}
        .feature-row {{ display: grid; grid-template-columns: 1fr 1.5fr; gap: 1rem; border-bottom: 1px solid var(--stone); padding: .8rem 0; }}
        .feature-name {{ font-family: 'IBM Plex Mono', monospace; font-size: .73rem; color: var(--forest); }} .feature-desc {{ color: var(--ink-soft); font-size: .9rem; }}
        [data-testid="stMetric"] {{ border-top: 1px solid var(--stone); padding-top: .75rem; }}
        [data-testid="stMetricLabel"] {{ color: var(--olive); }} [data-testid="stMetricValue"] {{ color: var(--forest); font-family: 'IBM Plex Mono', monospace; }}
        .stDataFrame {{ border: 1px solid var(--stone); }}
        .footer-note {{ border-top: 1px solid var(--stone); color: var(--ink-soft); font-family: 'IBM Plex Mono', monospace; font-size: .68rem; line-height: 1.7; padding: 1rem 0 2rem; margin-top: 2.5rem; }}
        .st-key-topbar {{ background: rgba(255,255,255,.88); border: 1px solid var(--stone); border-radius: 14px; padding: .55rem .7rem; margin: .8rem 0 1.6rem; box-shadow: 0 10px 26px rgba(7,17,31,.06); }}
        .st-key-topbar [data-testid="stHorizontalBlock"] {{ align-items: center; gap: .45rem; }}
        .nav-logo {{ display: flex; align-items: center; gap: .55rem; color: var(--dark) !important; font: 600 .82rem 'IBM Plex Mono', monospace; letter-spacing: .12em; white-space: nowrap; padding: .55rem .35rem; }}
        .nav-logo-mark {{ display: inline-grid; place-items: center; width: 1.9rem; height: 1.9rem; border-radius: 9px; background: var(--dark); color: var(--sage) !important; font: 1.25rem/1 'DM Serif Display', Georgia, serif; }}
        .st-key-topbar .stTextInput {{ margin: 0; }}
        .st-key-topbar .stTextInput input {{ min-height: 2.45rem; border-radius: 9px; background: var(--paper); border-color: var(--stone); padding-left: .9rem; }}
        .st-key-topbar .stTextInput label {{ display: none; }}
        .st-key-topbar .stButton > button {{ min-height: 2.45rem; border-radius: 9px; padding: .2rem .65rem; background: transparent; border-color: transparent; color: var(--forest); font-weight: 600; }}
        .st-key-topbar .stButton > button:hover {{ background: #E7F5F4; border-color: var(--stone); color: var(--dark); }}
        .st-key-topbar .stButton > button[kind="primary"] {{ background: var(--dark); color: var(--paper); border-color: var(--dark); }}
        .st-key-topbar .stButton > button[kind="primary"]:hover {{ background: var(--olive); border-color: var(--olive); }}
        .nav-divider {{ width: 1px; height: 1.65rem; background: var(--stone); margin: auto; }}
        .nav-icon-button {{ font-size: 1.05rem !important; }}
        .nav-search-icon {{ color: var(--olive); font: 1rem 'IBM Plex Mono', monospace; text-align: center; padding-top: .63rem; }}
        .site-footer {{ margin: 4.5rem -3rem -4rem; padding: 2.5rem 3rem 1.35rem; background: var(--dark); color: #D4E8EA; min-height: 185px; }}
        .site-footer * {{ color: #D4E8EA; }}
        .footer-grid {{ display: grid; grid-template-columns: 1.5fr 1fr 1fr 1fr; gap: 2rem; border-bottom: 1px solid rgba(169,217,211,.25); padding-bottom: 2rem; }}
        .footer-brand {{ font: 600 .78rem 'IBM Plex Mono', monospace; letter-spacing: .13em; color: var(--sage) !important; }}
        .footer-copy {{ max-width: 300px; font-size: .86rem; line-height: 1.55; margin-top: .65rem; color: #A9D9D3 !important; }}
        .footer-label {{ font: .64rem 'IBM Plex Mono', monospace; letter-spacing: .12em; text-transform: uppercase; color: var(--sage) !important; margin-bottom: .65rem; }}
        .footer-link {{ font-size: .83rem; line-height: 1.8; color: #D4E8EA !important; }}
        .footer-bottom {{ display: flex; justify-content: space-between; gap: 1rem; padding-top: 1rem; font: .63rem 'IBM Plex Mono', monospace; color: #A9D9D3 !important; }}
        .st-key-navrow {{ margin: -.55rem 0 1.8rem; }}
        .st-key-navrow .stButton > button {{ background: transparent; border-color: transparent; color: var(--ink-soft); min-height: 2.1rem; border-radius: 8px; font-weight: 600; }}
        .st-key-navrow .stButton > button:hover {{ background: #E7F5F4; color: var(--dark); border-color: var(--stone); }}
        .page-kicker {{ color: var(--olive); font: .7rem 'IBM Plex Mono', monospace; letter-spacing: .14em; text-transform: uppercase; margin: 1.6rem 0 .7rem; }}
        .page-intro {{ color: var(--ink-soft); font-size: 1rem; line-height: 1.6; max-width: 760px; margin-bottom: 1.5rem; }}
        .home-grid, .about-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin: 1.5rem 0 2.5rem; }}
        .info-card {{ background: #FFF; border: 1px solid var(--stone); border-radius: 12px; padding: 1.2rem; min-height: 145px; }}
        .info-card-icon {{ color: var(--olive); font: 1.25rem 'IBM Plex Mono', monospace; }}
        .info-card-title {{ color: var(--forest); font: 1.15rem 'DM Serif Display', Georgia, serif; margin: .55rem 0 .35rem; }}
        .info-card-copy {{ color: var(--ink-soft); font-size: .86rem; line-height: 1.5; }}
        .status-card {{ background: var(--forest); border-radius: 12px; color: var(--paper); padding: 1.3rem; min-height: 140px; }}
        .status-card * {{ color: var(--paper); }}
        .status-value {{ color: var(--sage) !important; font: 2.35rem 'DM Serif Display', Georgia, serif; margin-top: .5rem; }}
        .scan-result-card {{ border: 1px solid var(--sage); background: #E7F5F4; border-radius: 12px; padding: 1.4rem; margin: 1.2rem 0; }}
        .scan-result-card.phishing {{ border-color: #F3A65A; background: #FFF4E8; }}
        .scan-url {{ color: var(--forest); font: .78rem 'IBM Plex Mono', monospace; overflow-wrap: anywhere; margin-bottom: .7rem; }}
        .result-layout {{ display: grid; grid-template-columns: 1.1fr .9fr; gap: 1.2rem; align-items: start; }}
        .risk-meter {{ background: var(--stone); height: 9px; border-radius: 99px; overflow: hidden; margin: .75rem 0 1rem; }}
        .risk-meter-fill {{ background: var(--sage); height: 100%; border-radius: inherit; }}
        .risk-meter-fill.phishing {{ background: #F3A65A; }}
        .auth-card {{ max-width: 620px; background: #FFF; border: 1px solid var(--stone); border-radius: 14px; padding: 1.4rem; margin: 1.4rem 0 3rem; }}
        .dashboard-hero {{ background: linear-gradient(125deg, var(--dark), var(--forest)); border-radius: 14px; padding: 1.5rem; color: var(--paper); margin: 1.2rem 0; }}
        .dashboard-hero * {{ color: var(--paper); }}
        .dashboard-stat {{ background: #FFF; border: 1px solid var(--stone); border-radius: 12px; padding: 1rem; }}
        .dashboard-stat-label {{ color: var(--ink-soft); font: .68rem 'IBM Plex Mono', monospace; text-transform: uppercase; letter-spacing: .08em; }}
        .dashboard-stat-value {{ color: var(--forest); font: 2rem 'DM Serif Display', Georgia, serif; margin-top: .3rem; }}
        .step-line {{ display: grid; grid-template-columns: 2.2rem 1fr; gap: .9rem; align-items: start; margin: 1.2rem 0; }}
        .step-number {{ display: grid; place-items: center; width: 2.2rem; height: 2.2rem; border-radius: 50%; background: var(--dark); color: var(--sage); font: .72rem 'IBM Plex Mono', monospace; }}
        .step-title {{ color: var(--forest); font-weight: 700; margin-bottom: .2rem; }}
        .step-copy {{ color: var(--ink-soft); font-size: .9rem; line-height: 1.5; }}
        .brand-lockup {{ display: inline-flex; align-items: center; gap: .55rem; font-family: 'IBM Plex Mono', monospace; font-size: .72rem; letter-spacing: .18em; text-transform: uppercase; color: var(--sage) !important; margin-bottom: 1.3rem; position: relative; z-index: 1; }}
        .brand-mark {{ display: inline-grid; place-items: center; width: 1.65rem; height: 1.65rem; border: 1px solid var(--sage); border-radius: 50%; font: 1.25rem/1 'DM Serif Display', Georgia, serif; color: var(--sage); }}
        .trust-strip {{ display: flex; flex-wrap: wrap; gap: .7rem; margin-top: 1.1rem; }}
        .trust-chip {{ background: #E7F5F4; color: var(--forest); border: 1px solid var(--stone); padding: .4rem .65rem; font: .68rem 'IBM Plex Mono', monospace; letter-spacing: .04em; }}
        .stAlert {{ border-radius: 2px; }}
        @media (max-width: 760px) {{ .block-container {{ padding: 0 1.1rem 3rem; }} .masthead {{ margin: 0 -1.1rem 1.5rem; padding: 1.7rem 1.1rem 2rem; }} .feature-row {{ grid-template-columns: 1fr; gap: .25rem; }} .footer-grid {{ grid-template-columns: 1fr 1fr; gap: 1.4rem; }} .site-footer {{ margin-left: -1.1rem; margin-right: -1.1rem; padding-left: 1.1rem; padding-right: 1.1rem; }} .footer-bottom {{ flex-direction: column; }} .home-grid, .about-grid, .result-layout {{ grid-template-columns: 1fr; }} }}
        </style>
        """,
        unsafe_allow_html=True,
    )


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account", "update", "password",
    "bank", "bonus", "free", "wallet", "confirm", "paypal", "payment", "unlock", "credential",
]

FEATURE_LABELS = {
    "url_length": "URL length", "number_of_dots": "Dots", "contains_at_symbol": "@ symbol",
    "uses_https": "HTTPS", "contains_ip_address": "IP address", "suspicious_keyword_count": "Suspicious keywords",
    "hostname_length": "Hostname length", "path_length": "Path length", "number_of_hyphens": "Hyphens",
    "number_of_slashes": "Slashes", "number_of_digits": "Digits", "query_length": "Query length",
}


def is_ip_address(hostname: str) -> int:
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_features(url: str) -> dict[str, int]:
    clean_url = str(url).strip()
    normalized = clean_url if re.match(r"^[a-zA-Z]+://", clean_url) else f"http://{clean_url}"
    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""
    lower_url = clean_url.lower()
    return {
        "url_length": len(clean_url), "hostname_length": len(hostname), "path_length": len(parsed.path),
        "query_length": len(parsed.query), "number_of_dots": clean_url.count("."),
        "number_of_hyphens": clean_url.count("-"), "number_of_slashes": clean_url.count("/"),
        "number_of_digits": sum(character.isdigit() for character in clean_url),
        "contains_at_symbol": int("@" in clean_url), "uses_https": int(parsed.scheme.lower() == "https"),
        "contains_ip_address": is_ip_address(hostname),
        "suspicious_keyword_count": sum(keyword in lower_url for keyword in SUSPICIOUS_KEYWORDS),
    }


def demo_dataset() -> pd.DataFrame:
    safe_urls = [
        "https://www.google.com", "https://github.com/openai", "https://www.wikipedia.org/wiki/Phishing",
        "https://www.microsoft.com/en-us/security", "https://www.python.org/downloads/",
        "https://www.nasa.gov/missions", "https://www.bbc.com/news", "https://www.apple.com/support/",
        "https://www.mozilla.org/en-US/firefox/", "https://www.linkedin.com/", "https://www.amazon.com/",
        "https://www.nytimes.com/section/technology", "https://www.coursera.org/learn/python",
        "https://www.khanacademy.org/math", "https://www.w3.org/standards/",
        "https://docs.python.org/3/library/", "https://pandas.pydata.org/docs/",
        "https://scikit-learn.org/stable/", "https://www.cloudflare.com/learning/",
        "https://support.google.com/accounts/", "https://login.microsoftonline.com/",
        "https://www.paypal.com/us/home", "https://www.bankofamerica.com/",
        "https://www.dropbox.com/home", "https://www.reddit.com/r/security/",
        "https://stackoverflow.com/questions", "https://www.cisa.gov/topics/cyber-threats",
        "https://www.usa.gov/", "https://www.gov.uk/", "https://www.who.int/",
    ]
    phishing_urls = [
        "http://192.168.0.14/login/verify", "http://secure-account-update.com/login",
        "http://paypal-confirm-payment.net/verify/account", "http://bank-login-security.xyz/confirm",
        "http://45.77.12.4/secure/update-password", "http://free-bonus-wallet.com/signin",
        "http://account-verify-now.com/login?password=confirm", "http://secure-login-alert.net/account/update",
        "http://verify-paypal-user.com/credential/login", "http://login-security-check.org/confirm",
        "http://198.51.100.42/secure/bank/verify", "http://unlock-your-account.co/password",
        "http://appleid-confirmation.com/verify", "http://microsoft-security-alert.com/login",
        "http://signin-account-support.info/update", "http://bonus-free-gift.biz/claim/login",
        "http://paypal.com@security-check.net/login", "http://google.com@verify-account.co/secure",
        "http://account-login-verify.com/secure/confirm/payment", "http://banking-alerts.xyz/update/credential",
        "http://login-authentication-service.net/password/reset", "http://free-prize-wallet.com/verify/account",
        "http://verify-user-account.com/signin/secure", "http://secure-payment-confirmation.org/bank/login",
        "http://203.0.113.18/verify/login/account", "http://account-recovery-check.com/update/password",
        "http://paypal-security-verification.info/confirm", "http://bonus-login-claim.net/wallet/verify",
        "http://credential-update-alert.com/secure/login", "http://bank-account-unlock.com/signin",
    ]
    return pd.DataFrame({"url": safe_urls + phishing_urls, "label": [0] * len(safe_urls) + [1] * len(phishing_urls)})


def find_column(columns: list[str], candidates: list[str]) -> str | None:
    lowered = {str(column).lower().strip(): column for column in columns}
    for candidate in candidates:
        if candidate in lowered:
            return lowered[candidate]
    for column in columns:
        if any(candidate in str(column).lower() for candidate in candidates):
            return column
    return None


def normalize_dataset(raw: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    url_column = find_column(list(raw.columns), ["url", "link", "website", "address"])
    label_column = find_column(list(raw.columns), ["label", "type", "class", "status", "result"])
    if url_column is None or label_column is None:
        raise ValueError("Could not find URL and label columns. Expected names like URL and Label.")

    data = raw[[url_column, label_column]].dropna().copy()
    data.columns = ["url", "raw_label"]
    data["url"] = data["url"].astype(str).str.strip()
    data = data[data["url"].str.len() > 0].drop_duplicates(subset=["url"])
    raw_labels = data["raw_label"].astype(str).str.lower().str.strip()
    mapping = {
        "phishing": 1, "phish": 1, "malicious": 1, "suspicious": 1, "bad": 1, "fraud": 1, "1": 1,
        "legitimate": 0, "legit": 0, "benign": 0, "safe": 0, "good": 0, "valid": 0, "0": 0,
    }
    data["label"] = raw_labels.map(mapping)
    if data["label"].isna().any():
        numeric_labels = pd.to_numeric(data["raw_label"], errors="coerce")
        data["label"] = data["label"].fillna(numeric_labels.where(numeric_labels.isin([0, 1])))
    data = data.dropna(subset=["label"])
    data["label"] = data["label"].astype(int)
    if data["label"].nunique() != 2:
        raise ValueError("The dataset must contain both legitimate and phishing labels.")
    return data[["url", "label"]], f"{url_column} / {label_column}"


def train_models(data: pd.DataFrame) -> tuple[dict, pd.DataFrame, dict]:
    feature_frame = pd.DataFrame([extract_features(url) for url in data["url"]])
    X_train, X_test, y_train, y_test = train_test_split(
        feature_frame, data["label"], test_size=0.22, random_state=42, stratify=data["label"]
    )
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=240, max_depth=12, min_samples_leaf=2,
            class_weight="balanced_subsample", random_state=42,
        ),
        "Decision Tree": DecisionTreeClassifier(max_depth=10, class_weight="balanced", random_state=42),
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=2000, class_weight="balanced")),
        ]),
    }
    fitted, rows, test_predictions = {}, [], {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)
        fitted[name] = model
        test_predictions[name] = (y_test, predictions)
        rows.append({
            "Model": name, "Accuracy": accuracy_score(y_test, predictions),
            "Precision": precision_score(y_test, predictions, zero_division=0),
            "Recall": recall_score(y_test, predictions, zero_division=0),
            "F1 score": f1_score(y_test, predictions, zero_division=0),
        })
    return fitted, pd.DataFrame(rows).sort_values("F1 score", ascending=False).reset_index(drop=True), test_predictions


def explain_url(url: str) -> list[str]:
    values = extract_features(url)
    notes = []
    if values["contains_ip_address"]: notes.append("The hostname is an IP address")
    if values["contains_at_symbol"]: notes.append("The URL uses an @ symbol to obscure the destination")
    if not values["uses_https"]: notes.append("The address does not use HTTPS")
    if values["suspicious_keyword_count"]: notes.append(f"{values['suspicious_keyword_count']} security or credential keyword(s) detected")
    if values["url_length"] > 75: notes.append("The URL is unusually long")
    if values["number_of_dots"] >= 4: notes.append("The URL contains many dot-separated sections")
    return notes or ["No high-signal lexical warning was found"]


def render_metric_line(name: str, value: str) -> None:
    st.markdown(f'<div class="metric-line"><span class="metric-name">{name}</span><span class="metric-value">{value}</span></div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Urlora product views
# ---------------------------------------------------------------------------

def init_session() -> None:
    defaults = {
        "page": "Home",
        "url_to_check": "",
        "last_result": None,
        "scan_history": [],
        "user": None,
        "dataset": demo_dataset(),
        "dataset_note": "Demo dataset · upload a CSV to replace it",
        "header_url_input": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def render_header() -> None:
    with st.container(key="topbar", border=True):
        logo_col, search_col, search_icon_col, download_col, notification_col, support_col, auth_col = st.columns(
            [1.45, 3.15, .28, .45, .45, .45, 1.55], gap="small"
        )
        with logo_col:
            st.markdown('<div class="nav-logo"><span class="nav-logo-mark">⌁</span><span>URLORA</span></div>', unsafe_allow_html=True)
        with search_col:
            header_url = st.text_input(
                "Search URL", value=st.session_state.url_to_check, key="header_url_input",
                placeholder="Search or paste a URL to inspect", label_visibility="collapsed",
            )
        with search_icon_col:
            header_search_clicked = st.button("⌕", key="header_search", help="Inspect this URL", use_container_width=True)
        with download_col:
            download_clicked = st.button("⇩", key="download_files", help="Download files", use_container_width=True)
        with notification_col:
            notification_clicked = st.button("◔", key="notifications", help="View notifications", use_container_width=True)
        with support_col:
            support_clicked = st.button("?", key="contact_support", help="Contact support", use_container_width=True)
        with auth_col:
            sign_in_col, sign_up_col = st.columns([1, 1], gap="small")
            with sign_in_col:
                sign_in_clicked = st.button("Sign in", key="sign_in", use_container_width=True)
            with sign_up_col:
                sign_up_clicked = st.button("Sign up", key="sign_up", type="primary", use_container_width=True)

    if header_search_clicked and header_url.strip():
        st.session_state.url_to_check = header_url.strip()
        st.session_state.page = "URL Scanner"
        st.session_state.auto_scan = True
    elif download_clicked:
        st.session_state.page = "User Dashboard"
    elif sign_in_clicked:
        st.session_state.auth_mode = "Sign in"
        st.session_state.page = "Login / Signup"
    elif sign_up_clicked:
        st.session_state.auth_mode = "Sign up"
        st.session_state.page = "Login / Signup"

    if notification_clicked:
        st.toast("No new Urlora notifications.")
    if support_clicked:
        st.toast("Support is available through the project README.")

    with st.container(key="navrow"):
        nav_cols = st.columns([1, 1, 1, 1, 1], gap="small")
        nav_items = [("Home", "Home"), ("URL Scanner", "URL Scanner"), ("Result", "Result page"),
                     ("Dashboard", "User Dashboard"), ("About / How it works", "About / How it works")]
        for column, (label, destination) in zip(nav_cols, nav_items):
            with column:
                if st.button(label, key=f"nav_{destination}", use_container_width=True):
                    st.session_state.page = destination


def render_footer() -> None:
    st.markdown(
        '<footer class="site-footer"><div class="footer-grid">'
        '<div><div class="footer-brand">⌁ URLORA / URL INTELLIGENCE</div><div class="footer-copy">A clear first line of defense for suspicious links, built to explain the signal behind every verdict.</div></div>'
        '<div><div class="footer-label">Product</div><div class="footer-link">URL inspector<br>Model bench<br>Risk signals</div></div>'
        '<div><div class="footer-label">Resources</div><div class="footer-link">Dataset guide<br>Documentation<br>Safety notes</div></div>'
        '<div><div class="footer-label">Connect</div><div class="footer-link">Contact support<br>Privacy<br>Terms</div></div>'
        '</div><div class="footer-bottom"><span>URLORA / URL SECURITY LAB</span><span>Explainable screening · the destination is never opened</span></div></footer>',
        unsafe_allow_html=True,
    )


def render_masthead() -> None:
    st.markdown(
        '<section class="masthead"><div class="brand-lockup"><span class="brand-mark">⌁</span> URLORA / URL INTELLIGENCE</div><div class="masthead-title">Make the address<br>earn your trust.</div><div class="masthead-copy">An explainable phishing URL detector that reads the structure of an address before a page is opened. Urlora combines lightweight machine learning with clear signals so every result is easy to understand.</div><div class="masthead-meta"><span>01 / lexical inspection</span><span>02 / model comparison</span><span>03 / risk readout</span></div></section>',
        unsafe_allow_html=True,
    )


def render_dataset_setup() -> tuple[pd.DataFrame, str]:
    st.markdown('<div class="page-kicker">URLORA / DATA SOURCE</div>', unsafe_allow_html=True)
    st.markdown('<p class="page-intro">Upload a labelled CSV from Kaggle or UCI, or use Urlora’s built-in demo dataset for a complete judging flow.</p>', unsafe_allow_html=True)
    setup_left, setup_right = st.columns([1.4, 1], gap="large")
    with setup_left:
        st.markdown('<div class="control-panel"><div class="control-title">Labelled URL dataset</div>', unsafe_allow_html=True)
        uploaded_file = st.file_uploader("Upload CSV", type=["csv"], key="dataset_upload", label_visibility="collapsed")
        st.caption("Expected columns: URL / Link and Label / Type. Labels may be phishing and legitimate, or 1 and 0.")
        st.markdown('</div>', unsafe_allow_html=True)
    if uploaded_file is not None:
        try:
            data, column_source = normalize_dataset(pd.read_csv(uploaded_file))
            st.session_state.dataset = data
            st.session_state.dataset_note = f"Uploaded dataset · {column_source}"
        except Exception as error:
            st.error(str(error))
    data = st.session_state.dataset
    dataset_note = st.session_state.dataset_note
    with setup_right:
        st.markdown('<div class="control-panel"><div class="control-title">Current model state</div><div class="model-status">Random Forest / ready</div>', unsafe_allow_html=True)
        st.markdown(f'<span class="data-badge">{dataset_note}</span>', unsafe_allow_html=True)
        st.markdown(f'<div class="model-note" style="margin-top:.7rem">{len(data):,} labelled URLs · two-class classification</div></div>', unsafe_allow_html=True)
    return data, dataset_note


def render_model_bench(comparison: pd.DataFrame, test_predictions: dict, rf_test_labels: pd.Series) -> None:
    st.markdown('<div class="page-kicker">MODEL BENCH / 03</div>', unsafe_allow_html=True)
    st.header("Three models, one transparent decision")
    st.markdown('<p class="page-intro">Urlora compares Logistic Regression, Decision Tree, and Random Forest on the same holdout set. Random Forest powers the live scanner.</p>', unsafe_allow_html=True)
    table_left, table_right = st.columns([1.1, .9], gap="large")
    with table_left:
        display_comparison = comparison.copy()
        for metric in ["Accuracy", "Precision", "Recall", "F1 score"]:
            display_comparison[metric] = display_comparison[metric].map(lambda value: f"{value:.1%}")
        st.dataframe(display_comparison, use_container_width=True, hide_index=True)
        rf_row = comparison[comparison["Model"] == "Random Forest"].iloc[0]
        st.markdown(f'<p class="section-intro" style="margin-top:1rem">Random Forest accuracy <strong>{rf_row["Accuracy"]:.1%}</strong> · phishing recall <strong>{rf_row["Recall"]:.1%}</strong> · holdout rows <strong>{len(rf_test_labels)}</strong></p>', unsafe_allow_html=True)
    with table_right:
        rf_test_labels, rf_test_predictions = test_predictions["Random Forest"]
        fig, ax = plt.subplots(figsize=(5.2, 4.1), facecolor=PALETTE["paper"])
        ax.set_facecolor(PALETTE["paper"])
        ConfusionMatrixDisplay.from_predictions(rf_test_labels, rf_test_predictions, display_labels=["Safe", "Phishing"], cmap="GnBu", colorbar=False, ax=ax)
        ax.set_title("Random Forest confusion matrix", color=PALETTE["dark"], pad=14, fontsize=12)
        ax.set_xlabel("Predicted", color=PALETTE["forest"]); ax.set_ylabel("Actual", color=PALETTE["forest"]); ax.tick_params(colors=PALETTE["forest"])
        for spine in ax.spines.values(): spine.set_color(PALETTE["stone"])
        st.pyplot(fig, use_container_width=True); plt.close(fig)


def score_url(url: str, model) -> dict:
    clean_url = url.strip()
    values = extract_features(clean_url)
    frame = pd.DataFrame([values])
    prediction = int(model.predict(frame)[0])
    risk = float(model.predict_proba(frame)[0][1])
    return {
        "url": clean_url,
        "prediction": prediction,
        "risk": risk,
        "label": "PHISHING URL" if prediction else "LIKELY SAFE",
        "signals": explain_url(clean_url),
        "features": values,
        "timestamp": datetime.now().strftime("%d %b %Y, %H:%M"),
    }


def render_result(result: dict) -> None:
    is_phishing = result["prediction"] == 1
    result_class = "phishing" if is_phishing else ""
    meter_class = "phishing" if is_phishing else ""
    risk_percent = result["risk"] * 100
    st.markdown('<div class="page-kicker">RESULT PAGE / 02</div>', unsafe_allow_html=True)
    st.header("Your URL intelligence report")
    st.markdown('<p class="page-intro">Urlora inspected the visible address structure without opening the destination.</p>', unsafe_allow_html=True)
    st.markdown(f'<div class="scan-result-card {result_class}"><div class="scan-url">{result["url"]}</div><div class="result-layout"><div><div class="result-label">Random Forest verdict</div><div class="result-value {"danger" if is_phishing else "safe"}">{result["label"]}</div><div class="risk-number">phishing risk · {risk_percent:.1f}%</div><div class="risk-meter"><div class="risk-meter-fill {meter_class}" style="width:{max(4, risk_percent):.1f}%"></div></div><div class="model-note">Scanned {result["timestamp"]}</div></div><div><div class="result-label">Signal trace</div><div class="signal-list">' + '<br>'.join(f'• {note}' for note in result["signals"]) + '</div></div></div></div>', unsafe_allow_html=True)
    feature_left, feature_right = st.columns([1, 1], gap="large")
    with feature_left:
        st.subheader("Extracted signals")
        st.dataframe(pd.DataFrame({"Feature": list(result["features"].keys()), "Value": list(result["features"].values())}), use_container_width=True, hide_index=True)
    with feature_right:
        st.subheader("Next step")
        st.markdown("Treat this verdict as a screening signal. Do not enter credentials or payment details on a suspicious page.")
        action_one, action_two = st.columns(2, gap="small")
        with action_one:
            if st.button("Scan another URL", use_container_width=True):
                st.session_state.page = "URL Scanner"
                st.rerun()
        with action_two:
            if st.button("Open dashboard", use_container_width=True):
                st.session_state.page = "User Dashboard"
                st.rerun()


def render_home(data: pd.DataFrame, dataset_note: str, fitted_models: dict, comparison: pd.DataFrame, test_predictions: dict) -> None:
    st.markdown(f'<div class="home-grid"><div class="info-card"><div class="info-card-icon">⌕</div><div class="info-card-title">Scan before you click</div><div class="info-card-copy">Paste any address into the Urlora scanner and get a clear first-pass risk readout.</div></div><div class="info-card"><div class="info-card-icon">◌</div><div class="info-card-title">Understand the signal</div><div class="info-card-copy">See the lexical clues behind the prediction instead of receiving a black-box label.</div></div><div class="status-card"><div class="control-title" style="color:#A9D9D3">LIVE STATUS</div><div class="status-value">Ready to screen</div><div style="font-size:.86rem;margin-top:.45rem">{len(data):,} labelled URLs · 3 models</div></div></div>', unsafe_allow_html=True)
    if st.button("Open URL Scanner →", type="primary"):
        st.session_state.page = "URL Scanner"
        st.rerun()
    render_model_bench(comparison, test_predictions, test_predictions["Random Forest"][0])


def render_scanner(best_model) -> None:
    st.markdown('<div class="page-kicker">URL SCANNER / 01</div>', unsafe_allow_html=True)
    st.header("Inspect an address before you trust it")
    st.markdown('<p class="page-intro">Urlora analyzes the URL text only. It never visits the destination, follows redirects, or transmits the address to a third-party service.</p>', unsafe_allow_html=True)
    auto_scan = st.session_state.pop("auto_scan", False)
    current_value = st.session_state.url_to_check
    with st.container(key="inspector", border=True):
        st.markdown('<div class="inspector-label">Address under review</div>', unsafe_allow_html=True)
        url_value = st.text_input("URL to inspect", value=current_value, key="scanner_url_input", placeholder="https://example.com/account", label_visibility="collapsed")
        scan_clicked = st.button("Run safe scan", type="primary", use_container_width=True)
    if (scan_clicked or auto_scan) and url_value.strip():
        result = score_url(url_value, best_model)
        st.session_state.url_to_check = url_value.strip()
        st.session_state.last_result = result
        st.session_state.scan_history.insert(0, result)
        st.session_state.page = "Result page"
        st.rerun()
    elif scan_clicked or auto_scan:
        st.warning("Enter a URL to inspect.")
    st.markdown('<div class="home-grid"><div class="info-card"><div class="info-card-icon">01</div><div class="info-card-title">Structure</div><div class="info-card-copy">Length, dots, hyphens, slashes, digits, and query characters.</div></div><div class="info-card"><div class="info-card-icon">02</div><div class="info-card-title">Identity</div><div class="info-card-copy">Hostname shape, raw IP addresses, and user-info tricks like @.</div></div><div class="info-card"><div class="info-card-icon">03</div><div class="info-card-title">Language</div><div class="info-card-copy">Credential, payment, login, and verification words that raise risk.</div></div></div>', unsafe_allow_html=True)


def render_auth() -> None:
    mode = st.session_state.get("auth_mode", "Sign in")
    st.markdown('<div class="page-kicker">ACCOUNT ACCESS</div>', unsafe_allow_html=True)
    st.header("Keep your scans close")
    st.markdown('<p class="page-intro">Create a demo Urlora account to keep scan history and view personal statistics during this session.</p>', unsafe_allow_html=True)
    st.markdown('<div class="auth-card">', unsafe_allow_html=True)
    selected_mode = st.radio("Account mode", ["Sign in", "Sign up"], index=0 if mode == "Sign in" else 1, horizontal=True, label_visibility="collapsed")
    if selected_mode == "Sign up":
        with st.form("signup_form"):
            name = st.text_input("Name", placeholder="Your name")
            email = st.text_input("Email", placeholder="you@example.com")
            password = st.text_input("Password", type="password", placeholder="Create a password")
            submitted = st.form_submit_button("Create demo account", type="primary", use_container_width=True)
        if submitted:
            if not name.strip() or not email.strip() or not password.strip():
                st.error("Complete all fields to create your demo account.")
            else:
                st.session_state.user = {"name": name.strip(), "email": email.strip()}
                st.session_state.page = "User Dashboard"
                st.rerun()
    else:
        with st.form("signin_form"):
            email = st.text_input("Email", placeholder="you@example.com")
            password = st.text_input("Password", type="password", placeholder="Your password")
            submitted = st.form_submit_button("Sign in to Urlora", type="primary", use_container_width=True)
        if submitted:
            if not email.strip() or not password.strip():
                st.error("Enter your email and password.")
            else:
                existing_name = st.session_state.user["name"] if st.session_state.user else email.split("@")[0].title()
                st.session_state.user = {"name": existing_name, "email": email.strip()}
                st.session_state.page = "User Dashboard"
                st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
    st.caption("Demo note: authentication is session-based for this prototype. Add a database and password hashing before production use.")


def render_dashboard() -> None:
    user = st.session_state.get("user")
    if not user:
        st.markdown('<div class="page-kicker">USER DASHBOARD</div>', unsafe_allow_html=True)
        st.header("Your Urlora workspace")
        st.info("Sign in or create an account to see scan history and statistics.")
        if st.button("Go to Login / Signup", type="primary"):
            st.session_state.page = "Login / Signup"
            st.rerun()
        return
    history = st.session_state.scan_history
    phishing_count = sum(item["prediction"] for item in history)
    safe_count = len(history) - phishing_count
    avg_risk = sum(item["risk"] for item in history) / len(history) if history else 0
    st.markdown('<div class="page-kicker">USER DASHBOARD</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="dashboard-hero"><div class="brand-lockup">⌁ {user["name"].upper()} / PRIVATE WORKSPACE</div><h2 style="color:#F4F9FA !important;margin:.2rem 0">Your scan intelligence</h2><div style="color:#A9D9D3">A session-level view of the URLs you have inspected with Urlora.</div></div>', unsafe_allow_html=True)
    stat_cols = st.columns(4, gap="small")
    stats = [("Total scans", len(history)), ("Likely safe", safe_count), ("Flagged", phishing_count), ("Average risk", f"{avg_risk:.1%}")]
    for column, (label, value) in zip(stat_cols, stats):
        with column:
            st.markdown(f'<div class="dashboard-stat"><div class="dashboard-stat-label">{label}</div><div class="dashboard-stat-value">{value}</div></div>', unsafe_allow_html=True)
    st.markdown('<div class="page-kicker">SCAN HISTORY</div>', unsafe_allow_html=True)
    if history:
        history_frame = pd.DataFrame([{
            "Time": item["timestamp"], "URL": item["url"], "Verdict": item["label"], "Risk": f'{item["risk"]:.1%}'
        } for item in history])
        st.dataframe(history_frame, use_container_width=True, hide_index=True)
        st.download_button("Download scan history", history_frame.to_csv(index=False), "urlora-scan-history.csv", "text/csv")
    else:
        st.markdown('<div class="info-card"><div class="info-card-title">No scans yet</div><div class="info-card-copy">Your inspected URLs will appear here with their verdict, risk score, and timestamp.</div></div>', unsafe_allow_html=True)
    if st.button("Sign out", use_container_width=False):
        st.session_state.user = None
        st.session_state.page = "Home"
        st.rerun()


def render_about() -> None:
    st.markdown('<div class="page-kicker">ABOUT / HOW IT WORKS</div>', unsafe_allow_html=True)
    st.header("Explainable screening, in four steps")
    st.markdown('<p class="page-intro">Urlora is a machine-learning prototype for detecting suspicious URL patterns. It is designed to help people slow down before entering credentials or payment information.</p>', unsafe_allow_html=True)
    steps = [("01", "Paste the address", "The scanner accepts a URL as text and does not open it."), ("02", "Extract visible signals", "Urlora measures structure, hostname shape, HTTPS usage, IP hosts, and suspicious language."), ("03", "Compare model decisions", "Three classifiers learn from labelled legitimate and phishing examples."), ("04", "Read the verdict", "The result page shows a risk score and the signals that influenced it." )]
    for number, title, copy in steps:
        st.markdown(f'<div class="step-line"><div class="step-number">{number}</div><div><div class="step-title">{title}</div><div class="step-copy">{copy}</div></div></div>', unsafe_allow_html=True)
    st.markdown('<div class="about-grid"><div class="info-card"><div class="info-card-icon">✓</div><div class="info-card-title">What Urlora does</div><div class="info-card-copy">Classifies URL text, compares models, records session history, and explains high-signal warnings.</div></div><div class="info-card"><div class="info-card-icon">!</div><div class="info-card-title">What it does not do</div><div class="info-card-copy">It does not visit sites, validate a page’s content, or replace a security blocklist or browser warning.</div></div><div class="info-card"><div class="info-card-icon">→</div><div class="info-card-title">Production next step</div><div class="info-card-copy">Add persistent accounts, domain reputation, DNS, certificate, redirect, and blocklist signals.</div></div></div>', unsafe_allow_html=True)


init_session()
load_styles()
render_header()

page = st.session_state.page
if page == "Home":
    render_masthead()
    data, dataset_note = render_dataset_setup()
    if len(data) < 12:
        st.error("Use at least 12 labelled URLs, with examples in both classes.")
        st.stop()
    fitted_models, comparison, test_predictions = train_models(data)
    render_home(data, dataset_note, fitted_models, comparison, test_predictions)
elif page == "URL Scanner":
    data = st.session_state.dataset
    fitted_models, comparison, test_predictions = train_models(data)
    render_scanner(fitted_models["Random Forest"])
elif page == "Result page":
    if st.session_state.last_result:
        render_result(st.session_state.last_result)
    else:
        st.info("Run a URL scan to create a result report.")
        if st.button("Open URL Scanner", type="primary"):
            st.session_state.page = "URL Scanner"
            st.rerun()
elif page == "Login / Signup":
    render_auth()
elif page == "User Dashboard":
    render_dashboard()
elif page == "About / How it works":
    render_about()

render_footer()
st.stop()


load_styles()
if "url_to_check" not in st.session_state:
    st.session_state.url_to_check = ""

with st.container(key="topbar", border=True):
    logo_col, search_col, search_icon_col, download_col, notification_col, support_col, auth_col = st.columns(
        [1.45, 3.15, .28, .45, .45, .45, 1.55], gap="small"
    )
    with logo_col:
        st.markdown('<div class="nav-logo"><span class="nav-logo-mark">⌁</span><span>URLORA</span></div>', unsafe_allow_html=True)
    with search_col:
        header_url = st.text_input(
            "Search URL",
            value=st.session_state.url_to_check,
            key="header_url_input",
            placeholder="Search or paste a URL to inspect",
            label_visibility="collapsed",
        )
    with search_icon_col:
        header_search_clicked = st.button("⌕", key="header_search", help="Inspect this URL", use_container_width=True)
    with download_col:
        download_clicked = st.button("⇩", key="download_files", help="Download files", use_container_width=True)
    with notification_col:
        notification_clicked = st.button("◔", key="notifications", help="View notifications", use_container_width=True)
    with support_col:
        support_clicked = st.button("?", key="contact_support", help="Contact support", use_container_width=True)
    with auth_col:
        sign_in_col, sign_up_col = st.columns([1, 1], gap="small")
        with sign_in_col:
            sign_in_clicked = st.button("Sign in", key="sign_in", use_container_width=True)
        with sign_up_col:
            sign_up_clicked = st.button("Sign up", key="sign_up", type="primary", use_container_width=True)

if download_clicked:
    st.toast("Export controls are available in the model bench below.")
if notification_clicked:
    st.toast("No new Urlora notifications.")
if support_clicked:
    st.toast("Support: review the project README for setup and dataset guidance.")
if sign_in_clicked or sign_up_clicked:
    st.info("Account access is reserved for the production version of Urlora.")

st.markdown(
    '<section class="masthead"><div class="brand-lockup"><span class="brand-mark">⌁</span> URLORA / URL INTELLIGENCE</div><div class="masthead-title">Make the address<br>earn your trust.</div><div class="masthead-copy">An explainable phishing URL detector that reads the structure of an address before a page is opened. Urlora combines lightweight machine learning with clear signals so every result is easy to understand.</div><div class="masthead-meta"><span>01 / lexical inspection</span><span>02 / model comparison</span><span>03 / risk readout</span></div></section>',
    unsafe_allow_html=True,
)

st.markdown('<div class="section-kicker">URLORA / DATA SOURCE</div>', unsafe_allow_html=True)
st.markdown('<p class="section-intro">Bring a labelled CSV from Kaggle or UCI, or start with the small demonstration set included for the judging flow.</p>', unsafe_allow_html=True)
setup_left, setup_right = st.columns([1.4, 1], gap="large")
with setup_left:
    st.markdown('<div class="control-panel"><div class="control-title">Labelled URL dataset</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader("Upload CSV", type=["csv"], label_visibility="collapsed")
    st.caption("Expected columns: URL / Link and Label / Type. Labels may be phishing and legitimate, or 1 and 0.")
    st.markdown('</div>', unsafe_allow_html=True)

if uploaded_file is not None:
    try:
        data, column_source = normalize_dataset(pd.read_csv(uploaded_file))
        dataset_note = f"Uploaded dataset · {column_source}"
    except Exception as error:
        st.error(str(error))
        data, dataset_note = demo_dataset(), "Demo dataset · upload a CSV to replace it"
else:
    data, dataset_note = demo_dataset(), "Demo dataset · upload a CSV to replace it"

with setup_right:
    st.markdown('<div class="control-panel"><div class="control-title">Current model state</div><div class="model-status">Random Forest / ready</div>', unsafe_allow_html=True)
    st.markdown(f'<span class="data-badge">{dataset_note}</span>', unsafe_allow_html=True)
    st.markdown(f'<div class="model-note" style="margin-top:.7rem">{len(data):,} labelled URLs · two-class classification</div></div>', unsafe_allow_html=True)

if len(data) < 12:
    st.error("Use at least 12 labelled URLs, with examples in both classes.")
    st.stop()
try:
    fitted_models, comparison, test_predictions = train_models(data)
except ValueError as error:
    st.error(f"Training could not start: {error}")
    st.stop()

best_model = fitted_models["Random Forest"]
rf_test_labels, rf_test_predictions = test_predictions["Random Forest"]
rf_row = comparison[comparison["Model"] == "Random Forest"].iloc[0]

st.markdown('<div class="section-kicker">LIVE INSPECTION / 01</div>', unsafe_allow_html=True)
st.header("What does this address reveal?")
st.markdown('<p class="section-intro">Paste a URL below. Urlora analyzes the text only; it does not open the destination or make a network request.</p>', unsafe_allow_html=True)
with st.container(key="inspector", border=True):
    st.markdown('<div class="inspector-label">Address under review</div>', unsafe_allow_html=True)
    input_col, button_col = st.columns([4, 1], gap="medium")
    with input_col:
        url_value = st.text_input("URL to inspect", value=st.session_state.url_to_check, key="url_input", placeholder="https://example.com/account", label_visibility="collapsed")
    with button_col:
        inspect_clicked = st.button("Inspect URL", use_container_width=True)

url_source = header_url.strip() if header_search_clicked else url_value.strip()
inspect_requested = inspect_clicked or header_search_clicked
if inspect_requested and url_source:
    st.session_state.url_to_check = url_source
    url = st.session_state.url_to_check
    input_frame = pd.DataFrame([extract_features(url)])
    prediction = int(best_model.predict(input_frame)[0])
    risk = float(best_model.predict_proba(input_frame)[0][1])
    label = "PHISHING URL" if prediction == 1 else "LIKELY SAFE"
    css_class = "danger" if prediction == 1 else "safe"
    result_left, result_right = st.columns([1.1, .9], gap="large")
    with result_left:
        st.markdown(f'<div class="result-panel"><div class="result-label">Random Forest verdict</div><div class="result-value {css_class}">{label}</div><div class="risk-number">phishing risk · {risk:.1%}</div></div>', unsafe_allow_html=True)
    with result_right:
        st.markdown('<div class="section-kicker" style="margin-top:1.5rem">Signal trace</div>', unsafe_allow_html=True)
        st.markdown('<div class="signal-list">' + '<br>'.join(f'• {note}' for note in explain_url(url)) + '</div>', unsafe_allow_html=True)
elif inspect_requested:
    st.warning("Enter a URL to inspect.")

st.markdown('<div class="rule"></div>', unsafe_allow_html=True)
st.markdown('<div class="section-kicker">SIGNAL PROFILE / 02</div>', unsafe_allow_html=True)
st.header("The model reads the address, not the page")
st.markdown('<p class="section-intro">These are the visible clues that make the prediction explainable to a judge. They are extracted without visiting any website.</p>', unsafe_allow_html=True)
profile_left, profile_right = st.columns([1.1, .9], gap="large")
with profile_left:
    st.markdown('<div class="feature-table">', unsafe_allow_html=True)
    signal_rows = [
        ("URL length", "Longer addresses create more room for obfuscation"),
        ("Dots and hyphens", "Extra host sections can disguise a destination"),
        ("@ symbol", "Can hide the true hostname after user-info syntax"),
        ("HTTPS", "Shows encrypted transport, but is not proof of legitimacy"),
        ("IP address", "Raw IP hosts are less typical for public services"),
        ("Suspicious keywords", "Credential and payment language raises risk"),
    ]
    for name, description in signal_rows:
        st.markdown(f'<div class="feature-row"><div class="feature-name">{name}</div><div class="feature-desc">{description}</div></div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
with profile_right:
    st.markdown('<div class="section-kicker">Feature families</div>', unsafe_allow_html=True)
    render_metric_line("Structural", "length · dots · slashes")
    render_metric_line("Identity", "hostname · IP address")
    render_metric_line("Transport", "HTTPS presence")
    render_metric_line("Language", "login · verify · payment")
    st.markdown('<p class="section-intro" style="margin-top:1.2rem">The final classifier combines these small signals instead of relying on one hard-coded rule.</p>', unsafe_allow_html=True)
    st.markdown('<div class="trust-strip"><span class="trust-chip">NO PAGE VISITS</span><span class="trust-chip">EXPLAINABLE</span><span class="trust-chip">MODEL COMPARE</span></div>', unsafe_allow_html=True)

st.markdown('<div class="rule"></div>', unsafe_allow_html=True)
st.markdown('<div class="section-kicker">MODEL BENCH / 03</div>', unsafe_allow_html=True)
st.header("Random Forest is the live decision model")
st.markdown('<p class="section-intro">All three models use the same holdout set. Random Forest is selected for the judge-facing prediction because it handles interacting URL signals well.</p>', unsafe_allow_html=True)

table_left, table_right = st.columns([1.1, .9], gap="large")
with table_left:
    display_comparison = comparison.copy()
    for metric in ["Accuracy", "Precision", "Recall", "F1 score"]:
        display_comparison[metric] = display_comparison[metric].map(lambda value: f"{value:.1%}")
    st.dataframe(display_comparison, use_container_width=True, hide_index=True)
    st.markdown(f'<p class="section-intro" style="margin-top:1rem">Random Forest accuracy <strong>{rf_row["Accuracy"]:.1%}</strong> · phishing recall <strong>{rf_row["Recall"]:.1%}</strong> · holdout rows <strong>{len(rf_test_labels)}</strong></p>', unsafe_allow_html=True)

with table_right:
    fig, ax = plt.subplots(figsize=(5.2, 4.1), facecolor=PALETTE["paper"])
    ax.set_facecolor(PALETTE["paper"])
    ConfusionMatrixDisplay.from_predictions(rf_test_labels, rf_test_predictions, display_labels=["Safe", "Phishing"], cmap="Reds", colorbar=False, ax=ax)
    ax.set_title("Random Forest confusion matrix", color=PALETTE["dark"], pad=14, fontsize=12)
    ax.set_xlabel("Predicted", color=PALETTE["forest"]); ax.set_ylabel("Actual", color=PALETTE["forest"]); ax.tick_params(colors=PALETTE["forest"])
    for spine in ax.spines.values(): spine.set_color(PALETTE["stone"])
    st.pyplot(fig, use_container_width=True); plt.close(fig)

st.markdown('<div class="rule"></div>', unsafe_allow_html=True)
st.markdown('<div class="section-kicker">BOUNDARIES / 04</div>', unsafe_allow_html=True)
boundary_left, boundary_right = st.columns([1, 1], gap="large")
with boundary_left:
    st.subheader("What this prototype does")
    st.markdown("It classifies the visible URL string, compares three supervised models, and gives a risk readout without connecting to the entered address.")
with boundary_right:
    st.subheader("What a production version adds")
    st.markdown("Domain age, DNS, certificate, redirect, reputation, and blocklist signals should be added before taking action on a real user.")

st.markdown(
    '<footer class="site-footer"><div class="footer-grid">'
    '<div><div class="footer-brand">⌁ URLORA / URL INTELLIGENCE</div><div class="footer-copy">A clear first line of defense for suspicious links, built to explain the signal behind every verdict.</div></div>'
    '<div><div class="footer-label">Product</div><div class="footer-link">URL inspector<br>Model bench<br>Risk signals</div></div>'
    '<div><div class="footer-label">Resources</div><div class="footer-link">Dataset guide<br>Documentation<br>Safety notes</div></div>'
    '<div><div class="footer-label">Connect</div><div class="footer-link">Contact support<br>Privacy<br>Terms</div></div>'
    '</div><div class="footer-bottom"><span>URLORA / URL SECURITY LAB</span><span>Explainable screening · the destination is never opened</span></div></footer>',
    unsafe_allow_html=True,
)
