import pandas
import numpy
import matplotlib
import joblib
import flask
import sklearn

print("Oh yeah!!! Lets get thi party started")

import joblib
import pandas as pd

# Load model once
model = joblib.load("rf_ids_model.pkl")


def predict_traffic(input_data_dict):
    # Map frontend names to model feature names
    mapping = {
        "fwd_packet_length_max": "Fwd Packet Length Max",
        "fwd_packet_length_mean": "Fwd Packet Length Mean",
        "subflow_fwd_bytes": "Subflow Fwd Bytes",
        "packet_length_mean": "Packet Length Mean",
        "average_packet_size": "Average Packet Size",
        "psh_flag_count": "PSH Flag Count",
        "total_length_fwd_packets": "Total Length of Fwd Packets",
        "packet_length_variance": "Packet Length Variance",
        "bwd_packets_per_s": "Bwd Packets/s",
        "flow_duration": "Flow Duration"
    }

    # Apply mapping
    mapped_data = {}
    for key, value in input_data_dict.items():
        if key in mapping:
            mapped_data[mapping[key]] = value

    # convert to dataframe
    df = pd.DataFrame([mapped_data])

    # Fill missing features with 0
    expected_features = model.feature_names_in_

    for feature in expected_features:
        if feature not in df.columns:
            df[feature] = 0

    df = df[expected_features]  # ensure correct order
    # DEBUG
    print("\n=== DEBUG INFO ===")
    print("Expected Features:", list(expected_features)[:10], "...")
    print("Received Columns:", list(df.columns)[:10], "...")
    print("Input Row:\n", df.head())
    print("====================\n")

    # Prediction & Probability
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0][1]

    print("Prediction", prediction)
    print("Probability", probability)

    # OUTPUT
    if prediction == 1:
        return {
            "result": "ATTACK",
            "confidence": float(probability)
        }
    else:
        return {
            "result": "NORMAL",
            "confidence": float(1 - probability)
        }



# VERSION 2,0

import joblib
import pandas as pd

model = joblib.load("rf_ids_model.pkl")

def predict_traffic(input_data_dict):

    df = pd.DataFrame([input_data_dict])

    # FORCE correct structure
    df = df.reindex(columns=model.feature_names_in_, fill_value=0)

    # DEBUG
    print("=== INPUT CHECK ===")
    print(df.iloc[0].to_dict())
    print("===================")

    prediction = model.predict(df)[0]
    proba = model.predict_proba(df)[0]

    attack_index = list(model.classes_).index(1)
    attack_prob = proba[attack_index]

    return {
        "result": "ATTACK" if prediction == 1 else "NORMAL",
        "confidence": float(attack_prob)
    }