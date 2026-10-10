import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from detector import extract_features


DATASET = "dataset/new_dataset.csv"
MODEL_FILE = "model.pkl"

SAFE_SAMPLES = 50000
MALICIOUS_SAMPLES = 50000


def extract_dataset_features(data):
    """Extract the same URL features used by detector.py."""

    features = []

    total = len(data)

    for i, url in enumerate(data["url"]):

        if i % 5000 == 0:
            print(f"Extracting features: {i:,}/{total:,}")

        try:
            feature_row = extract_features(str(url))
            features.append(feature_row)

        except Exception:
            features.append({})

    return pd.DataFrame(features).fillna(0)


def main():

    print("=" * 60)
    print("MALICIOUS URL DETECTOR")
    print("RANDOM FOREST MODEL TRAINING")
    print("=" * 60)

    # --------------------------------------------------
    # Load dataset
    # --------------------------------------------------

    print("\nLoading dataset...")

    df = pd.read_csv(DATASET)

    print(f"Total URLs: {len(df):,}")

    # --------------------------------------------------
    # Check labels
    # --------------------------------------------------

    print("\nOriginal label distribution:")
    print(df["label"].value_counts())

    safe = df[df["label"] == 0]
    malicious = df[df["label"] == 1]

    print(f"\nSafe URLs:      {len(safe):,}")
    print(f"Malicious URLs: {len(malicious):,}")

    # --------------------------------------------------
    # Create balanced dataset
    # --------------------------------------------------

    safe_count = min(SAFE_SAMPLES, len(safe))
    malicious_count = min(MALICIOUS_SAMPLES, len(malicious))

    safe_sample = safe.sample(
        n=safe_count,
        random_state=42
    )

    malicious_sample = malicious.sample(
        n=malicious_count,
        random_state=42
    )

    data = pd.concat(
        [safe_sample, malicious_sample],
        ignore_index=True
    )

    data = data.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    print(f"\nTraining dataset: {len(data):,} URLs")

    print("\nBalanced labels:")
    print(data["label"].value_counts())

    # --------------------------------------------------
    # Extract features
    # --------------------------------------------------

    print("\nExtracting URL features...")
    print("Please wait...")

    X = extract_dataset_features(data)

    y = data["label"].astype(int)

    print("\nFeature extraction complete.")

    print("\nFeatures used by Random Forest:")

    for feature in X.columns:
        print(" -", feature)

    # --------------------------------------------------
    # Train / test split
    # --------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\nTraining samples:", len(X_train))
    print("Testing samples:", len(X_test))

    # --------------------------------------------------
    # Random Forest
    # --------------------------------------------------

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    print("Random Forest training completed.")

    # --------------------------------------------------
    # Prediction
    # --------------------------------------------------

    predictions = model.predict(X_test)

    # --------------------------------------------------
    # Evaluation
    # --------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print("\n" + "=" * 60)
    print("MODEL RESULTS")
    print("=" * 60)

    print(f"\nAccuracy: {accuracy:.4f}")

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Safe",
                "Malicious"
            ]
        )
    )

    print("\nConfusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    # --------------------------------------------------
    # Save model
    # --------------------------------------------------

    model_data = {
        "model": model,
        "features": list(X.columns)
    }

    joblib.dump(
        model_data,
        MODEL_FILE
    )

    print("\n" + "=" * 60)
    print("MODEL SAVED SUCCESSFULLY")
    print("=" * 60)

    print(f"\nFile: {MODEL_FILE}")

    print("\nYou can now connect this model to Flask.")


if __name__ == "__main__":
    main()