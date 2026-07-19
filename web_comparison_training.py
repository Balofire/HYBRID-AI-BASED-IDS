import numpy.random
import pandas as pd
import numpy
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_curve, auc
from sklearn.svm import LinearSVC
import matplotlib.pyplot as plt
import seaborn as sns
import joblib


with open("cisc_normalTraffic_train.txt", "r", encoding="utf-8", errors="ignore") as f:
    normal_requests = f.readlines()

with open("cisc_anomalousTraffic_test.txt", "r", encoding="utf-8", errors="ignore") as f:
    attack_requests = f.readlines()

print("I'm an Engineer and my code has started running...")
normal_requests = [r.strip() for r in normal_requests if r.strip()]
attack_requests = [r.strip() for r in attack_requests if r.strip()]

normal_labels = [0] * len(normal_requests)
attack_labels = [1] * len(attack_requests)

df_normal = pd.DataFrame({"request_text": normal_requests,"label": normal_labels})
df_attack = pd.DataFrame({"request_text": attack_requests,"label": attack_labels})
df = pd.concat([df_normal, df_attack], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)
df = df.sample(n=50000, random_state=42)

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split

X_text = df["request_text"]
y = df["label"]
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2,5), max_features=20000)
X = vectorizer.fit_transform(X_text)
print(X.shape)
print(df.head(10))

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#LOGISTIC REGRESSION
# Testing without being weighted
print("Logistic Regression metrics start here:")
from sklearn.linear_model import LogisticRegression
model = LogisticRegression(max_iter=1000, class_weight='balanced')
model.fit(X_train, y_train)
y_pred_lr = model.predict(X_test)
accuracy = model.score(X_test, y_test)
print("Accuracy(no weighting):", accuracy)
print("Classification Report(No weighting): ")
print(classification_report(y_test, y_pred_lr))


# SVM TRAINING
svm_model = LinearSVC(random_state=42, class_weight='balanced')


print("Training SVM model...")

svm_model.fit(X_train, y_train)

print("Training complete.")
y_pred_svm = svm_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred_svm)
print("SVM MODEL RESULTS:")
print(f"Accuracy: {accuracy:.5f}")
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred_svm))

# CONFUSION MATRIX

cm = confusion_matrix(y_test, y_pred_svm)

plt.figure(figsize=(6, 5))

sns.heatmap(
    cm,
    annot=True,
    fmt='d',
    cmap='Blues'
)

plt.title("SVM Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")

plt.show()