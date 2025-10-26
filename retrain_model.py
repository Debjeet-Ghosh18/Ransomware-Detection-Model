"""
Quick script to retrain the ransomware detection model
Fixes scikit-learn version compatibility issues
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
import joblib
import os

print("=" * 60)
print("🔄 Retraining Ransomware Detection Model")
print("=" * 60)

# Check scikit-learn version
import sklearn
print(f"\n📦 scikit-learn version: {sklearn.__version__}")

# Load dataset
print("\n📂 Loading dataset...")
try:
    # Try different possible paths
    data_paths = [
        "data/data_file.csv",
        "data_file.csv",
        r"D:\Downloads\data_file.csv"
    ]
    
    df = None
    for path in data_paths:
        try:
            df = pd.read_csv(path)
            print(f"✅ Loaded from: {path}")
            print(f"✅ Loaded {len(df)} samples")
            break
        except FileNotFoundError:
            continue
    
    if df is None:
        print("❌ Error: Could not find data_file.csv!")
        print("\nPlease ensure your CSV file is in one of these locations:")
        for path in data_paths:
            print(f"  - {path}")
        exit(1)
        
except Exception as e:
    print(f"❌ Error loading data: {e}")
    exit(1)

# Prepare data
print("\n🔧 Preparing data...")
# Keep only numeric columns
df = df.select_dtypes(include=[np.number])
df = df.fillna(0)

# Define target
target_col = 'Benign'
if target_col not in df.columns:
    print(f"❌ Error: Target column '{target_col}' not found!")
    print(f"Available columns: {df.columns.tolist()}")
    exit(1)

X = df.drop(columns=[target_col])
y = df[target_col]

print(f"✅ Features: {X.shape[1]}")
print(f"✅ Feature names: {X.columns.tolist()}")
print(f"✅ Samples: {X.shape[0]}")
print(f"✅ Class distribution: {y.value_counts().to_dict()}")

# Split data
print("\n✂️ Splitting data (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"✅ Training samples: {len(X_train)}")
print(f"✅ Test samples: {len(X_test)}")

# Train model
print("\n🤖 Training Random Forest model...")
print("⏳ This may take 1-2 minutes...")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    verbose=0
)

model.fit(X_train, y_train)
print("✅ Model trained successfully!")

# Evaluate
print("\n📊 Evaluating model on test set...")
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

accuracy = accuracy_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_prob)

print(f"\n🎯 Performance Metrics:")
print(f"   ✓ Accuracy:  {accuracy*100:.2f}%")
print(f"   ✓ ROC-AUC:   {roc_auc*100:.2f}%")

# Save model
print("\n💾 Saving model...")
os.makedirs("models", exist_ok=True)

model_data = {
    "model": model,
    "features": X.columns.tolist()
}

model_path = "models/ransomware_model.pkl"
joblib.dump(model_data, model_path)
print(f"✅ Model saved to: {model_path}")

# Verify saved model can be loaded
print("\n🔍 Verifying saved model...")
try:
    loaded_data = joblib.load(model_path)
    test_pred = loaded_data["model"].predict(X_test[:1])
    print("✅ Model verified - loads correctly!")
except Exception as e:
    print(f"❌ Error verifying model: {e}")

print("\n" + "=" * 60)
print("✅ SUCCESS! Model retrained and ready to use")
print("=" * 60)
print("\n🚀 Next step: Run your Streamlit app")
print("   Command: streamlit run app.py")
print()