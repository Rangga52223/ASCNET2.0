import numpy as np
from joblib import load
from tensorflow.keras.models import load_model
import asyncio
import websockets
import json
import pandas as pd
from datetime import datetime
import yaml
import joblib

# Load scaler and model
scaler = joblib.load('scaler1.pk')
model = load_model('detection_core1.h5')

# Fitur yang digunakan
features_columns = [' Fwd Packet Length Max', 'Init_Win_bytes_forward',' Fwd Packet Length Mean', ' Avg Fwd Segment Size',' Subflow Fwd Bytes', 'Subflow Fwd Packets', ' Destination Port',' Bwd Packet Length Min', ' act_data_pkt_fwd','Total Length of Fwd Packets']

# Ambang batas untuk mendeteksi nilai yang sangat besar
threshold = 1e6

# Fungsi untuk menangani nilai infinity dan standarisasi
def preprocess_features(data):
    df = pd.DataFrame([data], columns=features_columns)

    # Menangani nilai inf dan mengisi NaN
    for column in features_columns:
        max_value = df[column].max()
        if max_value > threshold:
            df[column].replace([np.inf, -np.inf], np.nan, inplace=True)
            df[column].fillna(df[column].max(), inplace=True)

    # Standarisasi
    scaled_features = scaler.transform(df)
    return scaled_features

# Fungsi prediksi
def predict(features):
    X_reshaped = features.reshape((features.shape[0], 1, features.shape[1]))
    prediction = model.predict(X_reshaped)
    return 1 if prediction >= 0.5 else 0

# Fungsi untuk menangani pesan yang diterima dari WebSocket
async def handle_message(websocket, path):
    async for message in websocket:
        data = json.loads(message)
        
        try:
            # Preprocess and predict
            features = preprocess_features(data)
            prediction = predict(features)
            prediction_label = "DDoS" if prediction == 0 else "Normal"
            
            log_message = f"{datetime.now()} - Prediction: {prediction_label}"
            print(log_message)

            # Kirim hasil prediksi ke client
            await websocket.send(f"Prediction: {prediction_label}")

        except Exception as e:
            print(f"Error during processing: {e}")

# Jalankan server WebSocket
async def main():
    config = yaml.safe_load(open('config.yaml'))
    server = await websockets.serve(handle_message, config['server']['host'], config['server']['port'])
    print(f"WebSocket server started at ws://{config['server']['host']}:{config['server']['port']}")
    await server.wait_closed()

# Mulai event loop
asyncio.run(main())