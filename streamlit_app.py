# Streamlit app for network anomaly detection using a trained autoencoder
import streamlit as st
import numpy as np
import pandas as pd
import joblib
from tensorflow.keras.models import load_model

# Load model and scaler
scaler = joblib.load("model/scaler.pkl")
model = load_model("model/autoencoder.h5")
threshold = 0.01  # Replace with your actual threshold

# Protocol encoding
protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2}

st.title("🚦 Network Traffic Anomaly Detector")
st.markdown("Enter traffic details below to check if the activity is normal or anomalous.")

# Input fields in sidebar
with st.sidebar:
    st.header("Input Features")
    protocol = st.selectbox("Protocol", options=list(protocol_map.keys()))
    source_port = st.number_input("Source Port", min_value=0, max_value=65535)
    destination_port = st.number_input("Destination Port", min_value=0, max_value=65535)
    bytes_sent = st.number_input("Bytes Sent", min_value=0)
    bytes_received = st.number_input("Bytes Received", min_value=0)
    packets_sent = st.number_input("Packets Sent", min_value=0)
    packets_received = st.number_input("Packets Received", min_value=0)
    duration = st.number_input("Duration (s)", min_value=0.0, format="%.2f")

# Calculate derived features
total_bytes = bytes_sent + bytes_received
total_packets = packets_sent + packets_received
protocol_encoded = protocol_map[protocol]

# Define input structure
input_df = pd.DataFrame([{
    "SourceIP": 0,
    "DestinationIP": 0,
    "SourcePort": source_port,
    "DestinationPort": destination_port,
    "Protocol": protocol_encoded,
    "BytesSent": bytes_sent,
    "BytesReceived": bytes_received,
    "PacketsSent": packets_sent,
    "PacketsReceived": packets_received,
    "Duration": duration,
    "TotalBytes": total_bytes,
    "TotalPackets": total_packets
}])

# Display raw input
with st.expander("🔍 Input Data"):
    st.write("Raw user input (pre-scaling):")
    st.dataframe(input_df)

# Scale input
input_scaled = scaler.transform(input_df)
reconstructed = model.predict(input_scaled)
reconstruction_error = np.mean(np.square(input_scaled - reconstructed))
prediction = int(reconstruction_error > threshold)

# Display result
st.markdown("---")
st.subheader("🧾 Prediction Result:")
if prediction == 1:
    st.error("🚨 Anomalous traffic detected!")
else:
    st.success("✅ Normal traffic detected.")
st.markdown(f"**Reconstruction Error**: `{reconstruction_error:.6f}`")
