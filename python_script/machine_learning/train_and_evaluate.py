import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Load the dataset
input_file = "large_sample.csv"
df = pd.read_csv(input_file)

# Drop non-feature columns if present
drop_cols = [col for col in ['Unnamed: 0'] if col in df.columns]
df = df.drop(columns=drop_cols)

# Convert boolean columns to int (if any)
bool_cols = df.select_dtypes(include=['bool']).columns
for col in bool_cols:
    df[col] = df[col].astype(int)

# Separate features and target
y = df['target']
X = df.drop(columns=['target'])

# Split into train and test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train a Random Forest model
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

# Predict on the test set
y_pred = clf.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

print("Model Evaluation Results:\n")
print(f"Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(report)
print("\nConfusion Matrix:")
print(cm)

# Save the model
joblib.dump(clf, "random_forest_trained.joblib")
print("\nModel saved as random_forest_trained.joblib")
