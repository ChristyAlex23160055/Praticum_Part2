import torch
import torch.nn as nn
from scapy.all import sniff, IP, TCP, UDP
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib  # For loading the scaler

# Define your autoencoder model class
# Adjust the input dimension based on the 7 features
input_dim = 7  # Update this to 7 instead of 603
model_path = 'ML/Model_Deployment/artifacts/12-12/enhanced_autoencoder_model_best_20241212_031320.pth'

# Modify the Autoencoder class accordingly
class EnhancedAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(EnhancedAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),  # Reduced layers due to fewer features
            nn.LeakyReLU(negative_slope=0.01),
            nn.Linear(64, 32),
            nn.LeakyReLU(negative_slope=0.01),
            nn.Linear(32, 16),
            nn.LeakyReLU(negative_slope=0.01)
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.LeakyReLU(negative_slope=0.01),
            nn.Linear(32, 64),
            nn.LeakyReLU(negative_slope=0.01),
            nn.Linear(64, input_dim),
            nn.Sigmoid()  # Output the reconstructed features
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

# Load the updated model (Note: This will need to be retrained if you're changing the architecture)

# Define the input dimension based on features
input_dim = 7  # SourcePort, DestinationPort, BytesSent, BytesReceived, PacketsSent, PacketsReceived, Duration

# Create a new model instance with the updated input dimension (7 features)
model = EnhancedAutoencoder(input_dim)

# Attempt to load pre-trained weights
try:
    pre_trained_model = torch.load(model_path)
    
    # Remove the keys that don't match the current model's architecture
    model_state_dict = model.state_dict()
    pre_trained_model = {k: v for k, v in pre_trained_model.items() if k in model_state_dict and v.size() == model_state_dict[k].size()}
    
    # Update the model with the compatible weights
    model_state_dict.update(pre_trained_model)
    model.load_state_dict(model_state_dict)
    
    # Ensure the model is in evaluation mode
    model.eval()
    print("Autoencoder model loaded and updated successfully.")
    
except FileNotFoundError:
    print(f"Model file not found at {model_path}. Please check the path.")
    exit(1)
except RuntimeError as e:
    print(f"Error loading the model: {e}")
    exit(1)

# Load your pre-trained StandardScaler
scaler_path = 'ML/Model_Deployment/artifacts/12-12/scaler_20241212_031320.joblib'
try:
    scaler = joblib.load(scaler_path)
    print("Scaler loaded successfully.")
except FileNotFoundError:
    print(f"Scaler file not found at {scaler_path}. Please check the path.")
    exit(1)

# Define a threshold for anomaly detection
threshold = 1.7  # Define a suitable threshold based on your training

# Function to preprocess packets and extract features
def preprocess_packet(packet):
    if IP in packet:
        # Extract features
        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
        bytes_sent = len(packet)
        bytes_received = 0  # Placeholder
        packets_sent = 1  # Placeholder
        packets_received = 0  # Placeholder
        duration = 0  # Placeholder

        # Return the feature vector with exactly 7 features
        features = np.array([src_port, dst_port, bytes_sent, bytes_received, packets_sent, packets_received, duration])
        return features
    return None

# Function to preprocess and predict anomalies
def preprocess_and_predict(features):
    # Ensure the feature vector has the correct dimensions (7)
    features_reshaped = np.array(features).reshape(1, -1)  # Shape (1, 7)

    # Scale the features (using the scaler trained on 7 features)
    try:
        scaled_features = scaler.transform(features_reshaped)
    except ValueError as e:
        print(f"Error during scaling: {e}")
        return

    # Convert to PyTorch tensor
    features_tensor = torch.tensor(scaled_features, dtype=torch.float32)

    # Feed to the model
    with torch.no_grad():
        reconstructed = model(features_tensor)

    # Calculate reconstruction error (MSE)
    mse_loss = nn.MSELoss()
    loss = mse_loss(reconstructed, features_tensor).item()
    limit=1.7

    # If the loss exceeds a certain threshold, it might be an anomaly
    if loss > threshold:
        print(f"Anomaly detected! Reconstruction loss: {loss:.6f}")
    else:
        print(f"Regular traffic. Reconstruction loss: {loss:.6f}")

# Function to process each captured packet
def process_packet(packet):
    features = preprocess_packet(packet)
    if features is not None:
        preprocess_and_predict(features)

# Start capturing packets on the desired interface
selected_interface = "Wi-Fi"  # Change this to your interface name
print("Starting packet capture...")
sniff(filter="ip", iface=selected_interface, prn=process_packet, store=0)
