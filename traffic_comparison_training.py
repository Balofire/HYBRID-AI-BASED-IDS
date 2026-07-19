import numpy.random
import pandas as pd
import numpy
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_curve, auc
from sklearn.svm import SVC
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# Reads baby_dataset into dataframe to be manipulated here
df = pd.read_csv("subset_dataset.csv")

# Converts object(written text) label to 0 and 1 (0= BENIGN, 1= ATTACK)
df['Attack Type'] = df['Attack Type'].apply(lambda x: 0 if x == 'Normal Traffic' else 1)

# FEATURES(X) VS LABELS(y)
X = df.drop('Attack Type', axis=1)
top_10_features = ["Fwd Packet Length Max", "Fwd Packet Length Mean", "Subflow Fwd Bytes", "Packet Length Mean", "Average Packet Size", "PSH Flag Count", "Total Length of Fwd Packets", "Packet Length Variance", "Bwd Packets/s", "Flow Duration"]

X_top10 = X[top_10_features]
y = df['Attack Type']
y_shuffle = numpy.random.permutation(y)

X_train, X_test, y_train, y_test = train_test_split(X_top10, y, test_size=0.2, random_state=42)
xgb_model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42)

xgb_model.fit(X_train, y_train)
y_pred_xgb = xgb_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred_xgb)

print("Accuracy:", accuracy)
print(classification_report(y_test, y_pred_xgb))

# SVM
# probability=True allows confidence scores later
svm_model = SVC(
    kernel='rbf',
    C=1.0,
    gamma='scale',
    probability=True,
    random_state=42
)


print("Training SVM model...")

svm_model.fit(X_train, y_train)

print("Training complete.")
y_pred = svm_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print("SVM MODEL RESULTS:")
print(f"Accuracy: {accuracy:.5f}")
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# CONFUSION MATRIX

cm = confusion_matrix(y_test, y_pred)

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

