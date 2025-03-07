from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.responses import JSONResponse
from scapy.all import sniff
from collections import defaultdict
import pandas as pd
from fastapi.middleware.cors import CORSMiddleware
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import joblib
import os
import subprocess

app = FastAPI()
print("Server Started")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Allow frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables to store captured packets and flows
captured_packets = []
flows = defaultdict(lambda: {
    'fwd_pkts': 0, 'bwd_pkts': 0,
    'fwd_len': 0, 'bwd_len': 0,
    'start_time': None, 'end_time': None
})

# Load the pre-trained model
MODEL_PATH = "./model/xgboost_model.pkl"
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")

# Function to handle packet capture
def packet_handler(packet):
    print("Packet captured!")  # Debug statement
    captured_packets.append(packet)
    if not packet.haslayer('IP'):
        return

    src_ip = packet['IP'].src
    dst_ip = packet['IP'].dst
    protocol = None
    dst_port = None

    if packet.haslayer('TCP'):
        protocol = 'TCP'
        dst_port = packet['TCP'].dport
    elif packet.haslayer('UDP'):
        protocol = 'UDP'
        dst_port = packet['UDP'].dport

    flow_key = (src_ip, dst_ip, dst_port, protocol)
    flow = flows[flow_key]

    # Initialize start_time if it's not set
    if flow['start_time'] is None:
        flow['start_time'] = packet.time

    # Update end_time for every packet
    flow['end_time'] = packet.time

    if src_ip == packet['IP'].src:
        flow['fwd_pkts'] += 1
        flow['fwd_len'] += len(packet)
    else:
        flow['bwd_pkts'] += 1
        flow['bwd_len'] += len(packet)

# Function to extract features from captured packets
def extract_features(packets):
    features_list = []
    for packet in packets:
        features = {}
        if packet.haslayer('IP'):
            features['Source IP'] = packet['IP'].src
            features['Destination IP'] = packet['IP'].dst
            features['Protocol'] = packet['IP'].proto
        else:
            features['Source IP'] = None
            features['Destination IP'] = None
            features['Protocol'] = None

        if packet.haslayer('TCP'):
            features['Source Port'] = packet['TCP'].sport
            features['Dst Port'] = packet['TCP'].dport
            features['Flags'] = str(packet['TCP'].flags)
            # Count SYN flags
            features['SYN Flag Cnt'] = 1 if 'S' in str(packet['TCP'].flags) else 0
        elif packet.haslayer('UDP'):
            features['Source Port'] = packet['UDP'].sport
            features['Dst Port'] = packet['UDP'].dport
            features['Flags'] = None
            features['SYN Flag Cnt'] = 0  # No SYN flag in UDP
        else:
            features['Source Port'] = None
            features['Dst Port'] = None
            features['Flags'] = None
            features['SYN Flag Cnt'] = 0  # No SYN flag in non-TCP/UDP packets

        features['Packet Length'] = len(packet)

        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            protocol = packet['IP'].proto

            if packet.haslayer('TCP'):
                dst_port = packet['TCP'].dport
            elif packet.haslayer('UDP'):
                dst_port = packet['UDP'].dport
            else:
                dst_port = None

            flow_key = (src_ip, dst_ip, dst_port, protocol)
            flow = flows[flow_key]

            # Ensure start_time and end_time are not None
            if flow['start_time'] is not None and flow['end_time'] is not None:
                flow_duration = flow['end_time'] - flow['start_time']
                flow_bytes_per_sec = (flow['fwd_len'] + flow['bwd_len']) / flow_duration if flow_duration > 0 else 0
                fwd_pkt_len_mean = flow['fwd_len'] / flow['fwd_pkts'] if flow['fwd_pkts'] > 0 else 0
                bwd_pkt_len_mean = flow['bwd_len'] / flow['bwd_pkts'] if flow['bwd_pkts'] > 0 else 0

                features['Flow Duration'] = flow_duration
                features['Flow Byts/s'] = flow_bytes_per_sec
                features['Fwd Pkt Len Mean'] = fwd_pkt_len_mean
                features['Bwd Pkt Len Mean'] = bwd_pkt_len_mean
                features['Tot Fwd Pkts'] = flow['fwd_pkts']
                features['Tot Bwd Pkts'] = flow['bwd_pkts']
            else:
                # Handle cases where start_time or end_time is None
                features['Flow Duration'] = 0
                features['Flow Byts/s'] = 0
                features['Fwd Pkt Len Mean'] = 0
                features['Bwd Pkt Len Mean'] = 0
                features['Tot Fwd Pkts'] = 0
                features['Tot Bwd Pkts'] = 0

        features_list.append(features)
    return features_list

# Function to preprocess the extracted features
def preprocess_features(df):
    # Fill missing values
    df['Source IP'].ffill(inplace=True)
    df['Destination IP'].ffill(inplace=True)
    df['Protocol'].ffill(inplace=True)
    df['Source Port'].fillna(df['Source Port'].mean(), inplace=True)
    df['Dst Port'].fillna(df['Dst Port'].mean(), inplace=True)
    df['Flow Byts/s'].fillna(df['Flow Byts/s'].mode()[0], inplace=True)
    df['Flow Duration'].fillna(df['Flow Duration'].mean(), inplace=True)

    # Encode categorical features
    le = LabelEncoder()
    df["Flags"] = le.fit_transform(df["Flags"])
    df['Flags'].fillna(df['Flags'].mean(), inplace=True)

    # Fill missing values for other columns
    df['Fwd Pkt Len Mean'].fillna(df['Fwd Pkt Len Mean'].mean(), inplace=True)
    df['Bwd Pkt Len Mean'].fillna(df['Bwd Pkt Len Mean'].mean(), inplace=True)
    df['Tot Fwd Pkts'].fillna(df['Tot Fwd Pkts'].mode()[0], inplace=True)
    df['Tot Bwd Pkts'].fillna(df['Tot Bwd Pkts'].mode()[0], inplace=True)
    df['SYN Flag Cnt'].fillna(0, inplace=True)  # Fill missing SYN Flag Cnt with 0

    # Select required columns
    required_columns = ["Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", 
                        "Fwd Pkt Len Mean", "Bwd Pkt Len Mean", "Flow Byts/s", "SYN Flag Cnt"]
    df = df[required_columns]

    # Normalize numerical features
    scaler = MinMaxScaler()
    df['Flow Byts/s'] = scaler.fit_transform(df[['Flow Byts/s']])
    df['Fwd Pkt Len Mean'] = scaler.fit_transform(df[['Fwd Pkt Len Mean']])
    df['Tot Fwd Pkts'] = scaler.fit_transform(df[['Tot Fwd Pkts']])
    df['Dst Port'] = scaler.fit_transform(df[['Dst Port']])

    return df

# Function to make predictions using the pre-trained model
def make_predictions(df):
    predictions = model.predict(df)
    return predictions.tolist()

# Endpoint to drop packets from a specific IP
@app.post("/drop-packets/")
async def drop_packets(ip: str):
    try:
        # Use iptables to drop packets from the specified IP
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return {"message": f"Packets from {ip} have been dropped."}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to drop packets: {str(e)}")

# Endpoint for live packet capture and prediction
@app.post("/start-capture-and-predict/") 
async def start_capture_and_predict():
    global captured_packets, flows
    captured_packets = []  # Reset captured packets
    flows = defaultdict(lambda: {
        'fwd_pkts': 0, 'bwd_pkts': 0,
        'fwd_len': 0, 'bwd_len': 0,
        'start_time': None, 'end_time': None
    })

    print("Starting packet capture...")
    sniff(iface="Wi-Fi", prn=packet_handler, count=500)  # Capture 500 packets
    print("Packet capture completed.")

    # Extract features from captured packets
    features_list = extract_features(captured_packets)

    # Preprocess features
    df = preprocess_features(pd.DataFrame(features_list))

    # Make predictions
    predictions = make_predictions(df)

    # Prepare packet data for response
    packet_data = []
    malicious_ips = set()  # Track malicious IPs
    for i, packet in enumerate(captured_packets):
        packet_info = {
            'Source IP': packet['IP'].src if packet.haslayer('IP') else None,
            'Destination IP': packet['IP'].dst if packet.haslayer('IP') else None,
            'Protocol': packet['IP'].proto if packet.haslayer('IP') else None,
            'Source Port': packet['TCP'].sport if packet.haslayer('TCP') else packet['UDP'].sport if packet.haslayer('UDP') else None,
            'Destination Port': packet['TCP'].dport if packet.haslayer('TCP') else packet['UDP'].dport if packet.haslayer('UDP') else None,
            'Packet Length': len(packet),
        }
        packet_data.append(packet_info)

        # If the packet is predicted as malicious, add the source IP to the malicious_ips set
        if predictions[i] == 1:
            malicious_ips.add(packet_info['Source IP'])

    # Drop packets from malicious IPs
    for ip in malicious_ips:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"Packets from {ip} have been dropped.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to drop packets from {ip}: {str(e)}")

    return JSONResponse(content={
        "message": "Packet capture, processing, and prediction completed.",
        "predictions": predictions,
        "packet_data": packet_data,
    })

# Endpoint for CSV file upload and prediction
@app.post("/predict-csv/")
async def predict_csv(file: UploadFile = File(...)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="File must be a CSV.")

    # Read the CSV file
    try:
        df = pd.read_csv(file.file)  # Read the CSV file first
        required_columns = ["Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", 
                            "Fwd Pkt Len Mean", "Bwd Pkt Len Mean", "Flow Byts/s", "SYN Flag Cnt"]
        df = df[required_columns]  # Select the required columns
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading CSV file: {str(e)}")

    # Make predictions
    predictions = make_predictions(df)

    # Prepare packet data for response
    packet_data = df.to_dict(orient="records")

    return JSONResponse(content={
        "message": "CSV file processed successfully.",
        "predictions": predictions,
        "packet_data": packet_data,
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
