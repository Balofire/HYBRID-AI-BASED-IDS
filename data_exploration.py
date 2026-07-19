import numpy.random
import pandas as pd
import numpy
from sklearn.metrics import classification_report
from sklearn.metrics import roc_curve, auc
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree

df = pd.read_csv("subset_dataset.csv")

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

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X_top10, y, test_size=0.2, random_state=42)

print(df['Attack Type'].value_counts())
print(df['Attack Type'].value_counts(normalize=True) * 100)

print("Malicious input values...")
print(X_test[y_test == 1].iloc[2])
print(X_test[y_test == 1].iloc[500])
print(X_test[y_test == 1].iloc[10000])

print("Normal input Values...")
print(X_test[y_test == 0].iloc[13000])
print(X_test[y_test == 0].iloc[3])
print(X_test[y_test == 0].iloc[5000])



