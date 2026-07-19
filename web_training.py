import numpy.random
import pandas as pd
import numpy
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_curve, auc
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree

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
df = df.sample(n=20000, random_state=42)

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split

X_text = df["request_text"]
y = df["label"]
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(X_text)
print(X.shape)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#DECISION TREE TRAININNG
print("Decision tree metrics start here:")
from sklearn.tree import DecisionTreeClassifier
dt_model = DecisionTreeClassifier(max_depth=10, random_state=42)
dt_model.fit(X_train,y_train)
y_pred_dt = dt_model.predict(X_test)
accuracy_dt = dt_model.score(X_test, y_test)
print("Decision Tree Accuracy =", accuracy_dt)
print(classification_report(y_test, y_pred_dt))

#RANDOM FOREST TRAINING
print("Beware the data of the random forrest, dont get lost!")
from sklearn.ensemble import RandomForestClassifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)
y_pred_rf = rf_model.predict(X_test)
accuracy_rf = rf_model.score(X_test, y_test)
print("RF Accuracy =", accuracy_rf)
print(classification_report(y_test, y_pred_rf))

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