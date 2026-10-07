# Urlora training data

The local training run used the UCI PhiUSIIL Phishing URL Dataset (dataset 967),
licensed CC BY 4.0:

- Source: https://archive.ics.uci.edu/dataset/967/phiusil-phishing-url-dataset
- Archive SHA-256: `0a639fd03aea630c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59`
- Rows downloaded: 235,795
- Publisher labels: `1 = legitimate`, `0 = phishing`
- Urlora labels after conversion: `0 = safe`, `1 = phishing`
- Invalid rows removed by the training script: 4
- Rows used for training/evaluation: 235,366

The archive is kept under `data/raw/` and the two-column converted file under
`data/processed/`; both are gitignored. The training command was:

```powershell
python -m backend.ml.train_model data/processed/phiusiil_urls.csv --output backend/ml/model/phishing_xgboost.pkl
```

The model uses only the raw URL column and Urlora's shared lexical feature
extractor. It should be treated as a first-pass screening model, not a complete
reputation or page-content detector. In particular, unseen short domains such as
`example.com` can be misclassified by lexical-only features.
