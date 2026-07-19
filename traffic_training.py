import numpy.random
import pandas as pd
import numpy
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_curve, auc
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree
from sklearn.svm import SVC
import joblib

# Reads subset_dataset into dataframe to be manipulated here
df = pd.read_csv("subset_dataset.csv")

# Converts object(written text) label to 0 and 1 (0= BENIGN, 1= ATTACK)
df['Attack Type'] = df['Attack Type'].apply(lambda x: 0 if x == 'Normal Traffic' else 1)

# FEATURES(X) VS LABELS(y)
X = df.drop('Attack Type', axis=1)
top_10_features = ["Fwd Packet Length Max",
                  "Fwd Packet Length Mean",
                  "Subflow Fwd Bytes",
                  "Packet Length Mean",
                  "Average Packet Size",
                  "PSH Flag Count",
                  "Total Length of Fwd Packets",
                  "Packet Length Variance",
                  "Bwd Packets/s",
                  "Flow Duration"]
X_top10 = X[top_10_features]
y = df['Attack Type']
y_shuffle = numpy.random.permutation(y)
# SPLIT DATA INTO TRAIN AND TEST (80% TRAIN 20% TEST)
X_train, X_test, y_train, y_test = train_test_split(X_top10, y, test_size=0.2, random_state=42)

#Malicous and Normal Data for manual input
print("Malicious input values...")
print(X_test[y_test == 1].iloc[2])
print(X_test[y_test == 1].iloc[500])
print(X_test[y_test == 1].iloc[10000])

print("Normal input Values...")
print(X_test[y_test == 0].iloc[13000])
print(X_test[y_test == 0].iloc[3])
print(X_test[y_test == 0].iloc[5000])

#LOGISTIC REGRESSION
# Testing without being weighted
print("Logistic Regression metrics start here:")
from sklearn.linear_model import LogisticRegression
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
accuracy = model.score(X_test, y_test)
print("Accuracy(no weighting):", accuracy)
print("Classification Report(No weighting): ")
print(classification_report(y_test, y_pred))

# LR GRAPHS
"""y_probs = model.predict_proba(X_test)[:, 1]

fpr, tpr, _ = roc_curve(y_test, y_probs)
roc_auc = auc(fpr, tpr)

plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}") # ROC curve
plt.plot([0, 1], [0, 1])
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve - Logistic Regression")
plt.legend()
plt.show()

cm = confusion_matrix(y_test, y_pred) # Confusion Matrix
sns.heatmap(cm, annot=True, fmt='d')
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix - Logistic Regression")
plt.show()"""

# Testing while weighted
"""b_model = LogisticRegression(max_iter=1000, class_weight='balanced')
b_model.fit(X_train, y_train)
b_y_pred = model.predict(X_test)
b_accuracy = model.score(X_test, y_test)
print("Accuracy(Weighted):", b_accuracy)
print("Classification Report(Weighted): ")
print(classification_report(y_test, b_y_pred))""" # Weighting made no difference because the dataset is balanced

# Decision Tree Training
print("Decision tree metrics start here:")
from sklearn.tree import DecisionTreeClassifier
dt_model = DecisionTreeClassifier(max_depth=1, random_state=42)
dt_model.fit(X_train,y_train)
y_pred_dt = dt_model.predict(X_test)
accuracy_dt = dt_model.score(X_test, y_test)
print("Decision Tree Accuracy =", accuracy_dt)
print(classification_report(y_test, y_pred_dt))

# DT GRAPHS
"""plt.figure(figsize=(12, 8)) # Visualization
plot_tree(dt_model, max_depth=1, feature_names=X.columns, filled=True)
plt.title("Decision Tree Visualization")
plt.show()

dt_feat_imp = dt_model.feature_importances_  # Feature Importance
dt_imp_df = pd.DataFrame({
    'Feature': X.columns,
    'Importance': dt_feat_imp
})
dt_imp_df = dt_imp_df.sort_values(by='Importance', ascending=False)
print(dt_imp_df.sample(10))
print("Duplicated Rows =", df.duplicated().sum())

dt_imp_df.head(10).plot(
    x = 'Feature',
    y = 'Importance',
    kind = 'bar')

plt.title("Top 10 Important Features (Decision Tree)")
plt.tight_layout()
plt.show()"""

# Random Forrest Training
print("Random Forest Metrics start here: ...")
from sklearn.ensemble import RandomForestClassifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)
y_pred_rf = rf_model.predict(X_test)
accuracy_rf = rf_model.score(X_test, y_test)
print("RF Accuracy =", accuracy_rf)
print(classification_report(y_test, y_pred_rf))

#RF ROC CURVE
"""y_probs = rf_model.predict_proba(X_test)[:, 1]

fpr, tpr, _ = roc_curve(y_test, y_probs)
roc_auc = auc(fpr, tpr)

plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}") # ROC curve
plt.plot([0, 1], [0, 1])
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve - Random Forest")
plt.legend()
plt.show()"""

# PLOTTING GRAPHS FOR DOCUMENTATION
# Accuracy comparison
"""models = ['Logistic Regression','Decision Tree','Random Forest']

f1_scores = [0.94, 0.94, 1.00]
recalls = [0.94, 0.99, 1.00]
precisions = [0.94, 0.89, 1.00]

# Accuracy
accuracies = [accuracy, accuracy_dt, accuracy_rf]
plt.bar(models, accuracies)
plt.title("Model Accuracy Comparison")
plt.xlabel("Models")
plt.ylabel("Accuracy")
plt.show()

# F1 Scores
plt.bar(models, f1_scores)
plt.title("Model F1 Score Comparison")
plt.xlabel("Models")
plt.ylabel("F1 Score")
plt.show()

# Recalls
plt.bar(models, recalls)
plt.title("Model Recall Comparison")
plt.xlabel("Models")
plt.ylabel("Recall")
plt.show()

# Precisions
plt.bar(models, precisions)
plt.title("Model Precision Comparison")
plt.xlabel("Models")
plt.ylabel("Precision")
plt.show()"""

# XGBOOST (Extreme Gradient Boosting) TRAINING
print("XGBOOST Metrics start here: ...")
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

# Checking why the trees are so accurate to see if they are cheating
#print(X_top10)
feat_imp = rf_model.feature_importances_
imp_df = pd.DataFrame({
    'Feature': X_top10.columns,
    'Importance': feat_imp
})
imp_df = imp_df.sort_values(by='Importance', ascending=False)
print(imp_df.head(10))


imp_df.head().plot(               #RF FEATURES
    x='Feature',
    y='Importance',
    kind='bar')

plt.title("Top Important Features")
plt.tight_layout()
plt.show()


# Saving the best model
'''import joblib
joblib.dump(rf_model, "rf_ids_top10.pkl")
print("Model Saved WooooHoooo!!")'''