import joblib
import pandas as pd
import numpy.random
import numpy
from sklearn.metrics import classification_report
from sklearn.metrics import roc_curve, auc
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree

model = joblib.load("rf_ids_model.pkl")
print("Model Loaded Woohoo!!!")

df = pd.read_csv("subset_dataset.csv")

df['Attack Type'] = df['Attack Type'].apply(lambda x: 0 if x == 'Normal Traffic' else 1)

# FEATURES(X) VS LABELS(y)
X = df.drop('Attack Type', axis=1)
y = df['Attack Type']
y_shuffle = numpy.random.permutation(y)

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(model.predict(X_test[y_test == 1].iloc[:10]))
print(X_test.describe())
print(X_test.iloc[0])
