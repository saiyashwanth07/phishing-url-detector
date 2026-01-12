import joblib
import pandas as pd
from sklearn.metrics import classification_report

df = pd.read_csv("phishing_features.csv")
label_map = {"benign":0,"phishing":1,"defacement":2}
df["label"] = df["label"].map(label_map)

X = df.drop("label",axis=1)
y = df["label"]

model = joblib.load("../model/phishing_detector_xgboost.pkl")
scaler = joblib.load("../model/scaler.pkl")

X_scaled = scaler.transform(X)
pred = model.predict(X_scaled)

print(classification_report(y,pred))
