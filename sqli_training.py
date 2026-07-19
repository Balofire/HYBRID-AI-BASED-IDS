import numpy.random
import pandas as pd
import numpy
from sklearn.metrics import classification_report, accuracy_score
from sklearn.metrics import roc_curve, auc
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.svm import LinearSVC

# Reads subset_dataset into dataframe to be manipulated here
df = pd.read_csv("Modified_SQL_Dataset.csv")

#Assigning labels and features (X=feature, y=label)
X = df['Query']
y = df['Label']


# TRAIN-TEST SPLIT
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# TF-IDF VECTORIZATION
vectorizer = TfidfVectorizer(
    analyzer='char',
    ngram_range=(2, 5)
)

X_train_vectorized = vectorizer.fit_transform(X_train)
X_test_vectorized = vectorizer.transform(X_test)

# LOGISTIC REGRESSION MODEL
"""print("Logistic Regression Metrics start here: ...")
model = LogisticRegression(
    class_weight='balanced',
    max_iter=1000
)

# TRAIN MODEL
model.fit(X_train_vectorized, y_train)

# PREDICTIONS
y_pred_lr = model.predict(X_test_vectorized)

# EVALUATION
print("Accuracy:", accuracy_score(y_test, y_pred_lr))

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred_lr))


#Decision Tree TRAINING
print("Decision tree metrics start here:")
from sklearn.tree import DecisionTreeClassifier
dt_model = DecisionTreeClassifier(max_depth=1, random_state=42)
dt_model.fit(X_train_vectorized,y_train)
y_pred_dt = dt_model.predict(X_test_vectorized)
accuracy_dt = dt_model.score(X_test_vectorized, y_test)
print("Decision Tree Accuracy =", accuracy_dt)
print(classification_report(y_test, y_pred_dt))"""

#Random Forest TRAINING
print("Random Forest Metrics start here: ...")
from sklearn.ensemble import RandomForestClassifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train_vectorized, y_train)
y_pred_rf = rf_model.predict(X_test_vectorized)
accuracy_rf = rf_model.score(X_test_vectorized, y_test)
print("RF Accuracy =", accuracy_rf)
print(classification_report(y_test, y_pred_rf))

# XGBOOST TRAINING
"""print("XGBOOST Metrics start here: ...")
xgb_model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42)

xgb_model.fit(X_train_vectorized, y_train)
y_pred_xgb = xgb_model.predict(X_test_vectorized)
accuracy = accuracy_score(y_test, y_pred_xgb)

print("Accuracy:", accuracy)
print(classification_report(y_test, y_pred_xgb))

#SVM TRAINING
svm_model = LinearSVC(random_state=42, class_weight='balanced')
print("Training SVM model...")
svm_model.fit(X_train_vectorized, y_train)
print("Training complete.")
y_pred_svm = svm_model.predict(X_test_vectorized)
accuracy = accuracy_score(y_test, y_pred_svm)
print("SVM Metrics start here:")
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

plt.show()"""

import joblib
joblib.dump(rf_model, "rf_ids_sqli.pkl")
joblib.dump(vectorizer, "vector_sqli.pkl")
print("Models Saved WooooHoooo!!")
