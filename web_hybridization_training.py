import pandas as pd
import numpy.random
import numpy as np
import re
from xgboost import XGBClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.svm import LinearSVC
from scipy.sparse import hstack
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree


with open("cisc_normalTraffic_train.txt", "r", encoding="utf-8", errors="ignore") as f:
    normal_requests = f.readlines()

with open("cisc_anomalousTraffic_test.txt", "r", encoding="utf-8", errors="ignore") as f:
    attack_requests = f.readlines()

print("I'm an Engineer and my code has started working...")
normal_requests = [r.strip() for r in normal_requests if r.strip()]
attack_requests = [r.strip() for r in attack_requests if r.strip()]

normal_labels = [0] * len(normal_requests)
attack_labels = [1] * len(attack_requests)

df_normal = pd.DataFrame({
    "request_text": normal_requests,
    "label": normal_labels
})

df_attack = pd.DataFrame({
    "request_text": attack_requests,
    "label": attack_labels
})

df = pd.concat([df_normal, df_attack], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)
df = df.sample(n=100000, random_state=42)

vectorizer = TfidfVectorizer(
    analyzer='char_wb',
    ngram_range=(3,5),
    max_features=30000,
    lowercase=True
)

X_text = vectorizer.fit_transform(df["request_text"])
def extract_security_features(request):

    request = str(request)

    features = [
        len(request),                         # Request length
        request.count("'"),                  # Single quotes
        request.count('"'),                  # Double quotes
        request.count("="),                  # Equals signs
        request.count("/"),                  # Slashes
        request.count(";"),                  # Semicolons
        request.count("--"),                 # SQL comments
        int("union" in request.lower()),     # UNION keyword
        int("select" in request.lower()),    # SELECT keyword
        int("<script>" in request.lower()),  # XSS
        int("drop" in request.lower()),      # DROP keyword
        int("insert" in request.lower()),    # INSERT keyword
        int("http" in request.lower()),      # HTTP keyword
        int("admin" in request.lower()),     # admin targeting
    ]

    return features

security_features = np.array(
    df["request_text"].apply(extract_security_features).tolist()
)

X = hstack([X_text, security_features])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

#XGBOOST TRAINING
print("Extreme Gradient Booooost! ...")
xgb_model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42)

xgb_model.fit(X_train, y_train)
y_pred_xg = xgb_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred_xg)

print("Accuracy:", accuracy)
print(classification_report(y_test, y_pred_xg))

#LINEAR SVC MODEL
print("Linear SVC has begun its training...")
model = LinearSVC(
    class_weight='balanced',
    random_state=42
)

model.fit(X_train, y_train)
y_pred_svc = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred_svc)

print("Accuracy:", accuracy)

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred_svc))

print("\nConfusion Matrix:\n")
print(confusion_matrix(y_test, y_pred_svc))
