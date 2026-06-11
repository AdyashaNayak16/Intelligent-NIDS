import joblib
import pandas as pd
model=joblib.load("data/xgboost_ids_model.pkl")
feature_order=joblib.load("data/deployment_features.pkl")

def detect_ml_attack(flow_features):
    df=pd.DataFrame([flow_features])
    df=df[feature_order]
    prediction=model.predict(df)[0]
    if prediction==0:

        return "BENIGN"
    else:
        return "BOT"
test_flow = {
    'Destination Port': 80,
    'Flow Duration': 100,
    'Total Fwd Packets': 10,
    'Total Backward Packets': 5,
    'Total Length of Fwd Packets': 1000,
    'Total Length of Bwd Packets': 500,
    'Flow Bytes/s': 15,
    'Flow Packets/s': 2,
    'Packet Length Mean': 100,
    'Packet Length Std': 10,
    'SYN Flag Count': 1,
    'ACK Flag Count': 5,
    'RST Flag Count': 0,
    'PSH Flag Count': 0,
    'Average Packet Size': 100
}


