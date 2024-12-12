import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_curve, auc, precision_recall_curve
import joblib
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns

# Device selection
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f'Using device: {device}')

# Autoencoder architecture
class EnhancedAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(EnhancedAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 512),
            nn.LeakyReLU(negative_slope=0.01),
            nn.BatchNorm1d(512),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.LeakyReLU(negative_slope=0.01),
            nn.BatchNorm1d(256),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.LeakyReLU(negative_slope=0.01)
        )
        self.decoder = nn.Sequential(
            nn.Linear(128, 256),
            nn.LeakyReLU(negative_slope=0.01),
            nn.BatchNorm1d(256),
            nn.Dropout(0.3),
            nn.Linear(256, 512),
            nn.LeakyReLU(negative_slope=0.01),
            nn.BatchNorm1d(512),
            nn.Dropout(0.3),
            nn.Linear(512, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

# Load and preprocess data (replace 'your_data.csv' with your file path)
try:
    data = pd.read_csv('Kali/live_capture.csv')
except FileNotFoundError:
    print("Error: 'your_data.csv' not found. Please provide a valid file path.")
    exit()

# Handle missing values (example: fill with mean for numerical columns)
numerical_cols = ['SourcePort', 'DestinationPort', 'BytesSent', 'BytesReceived', 'PacketsSent', 'PacketsReceived', 'Duration']
for col in numerical_cols:
    data[col] = data[col].fillna(data[col].mean())

#One-hot encode categorical features
categorical_cols = ['SourceIP', 'DestinationIP', 'Protocol']
enc = OneHotEncoder(handle_unknown='ignore')
encoded_data = enc.fit_transform(data[categorical_cols]).toarray()
encoded_df = pd.DataFrame(encoded_data, columns=enc.get_feature_names_out(categorical_cols))
data = data.drop(columns=categorical_cols)
data = pd.concat([data, encoded_df], axis=1)

#Ensure that Malicious column is numeric. If not, convert it.
data['Malicious'] = data['Malicious'].str.lower()
data['Malicious'] = data['Malicious'].replace({'benign': 0, 'malicious': 1})
data['Malicious'] = pd.to_numeric(data['Malicious'], errors='coerce')
data = data.dropna(subset=['Malicious'])

# Separate features and labels
features = data.drop(columns=['Malicious'])
labels = data['Malicious'].astype(int)

# Scale numerical features
scaler = StandardScaler()
numerical_features = data[numerical_cols]
scaled_numerical_features = scaler.fit_transform(numerical_features)
scaled_numerical_df = pd.DataFrame(scaled_numerical_features, columns=numerical_cols)
features = features.drop(columns=numerical_cols)
features = pd.concat([features, scaled_numerical_df], axis=1)


# Split data (80% train, 10% val, 10% test)  using stratify for balanced classes
train_val_features, test_features, train_val_labels, test_labels = train_test_split(
    features, labels, test_size=0.1, random_state=42, stratify=labels
)
train_features, val_features, train_labels, val_labels = train_test_split(
    train_val_features, train_val_labels, test_size=0.111, random_state=42, stratify=train_val_labels
)

print(f"Train set shape: {train_features.shape}")
print(f"Validation set shape: {val_features.shape}")
print(f"Test set shape: {test_features.shape}")

# Convert to tensors
train_tensor = torch.tensor(train_features.values, dtype=torch.float32)
val_tensor = torch.tensor(val_features.values, dtype=torch.float32)
test_tensor = torch.tensor(test_features.values, dtype=torch.float32)

train_labels = train_labels.astype(np.float32).values
val_labels = val_labels.astype(np.float32).values
test_labels = test_labels.astype(np.float32).values

train_dataset = TensorDataset(train_tensor, torch.tensor(train_labels, dtype=torch.float32))
val_dataset = TensorDataset(val_tensor, torch.tensor(val_labels, dtype=torch.float32))
test_dataset = TensorDataset(test_tensor, torch.tensor(test_labels, dtype=torch.float32))

batch_size = 64
train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

# Initialize model, loss, and optimizer
input_dim = features.shape[1]
autoencoder = EnhancedAutoencoder(input_dim).to(device)
criterion = nn.MSELoss()
optimizer = optim.Adam(autoencoder.parameters(), lr=0.00005, weight_decay=1e-5)
scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=20, gamma=0.5)

# Training loop
epochs = 3 #Reduced for faster testing. Increase for better results
best_val_loss = float('inf')
patience = 10
epochs_without_improvement = 0

for epoch in range(epochs):
    autoencoder.train()
    epoch_loss = 0
    for batch_features, _ in train_loader:
        batch_features = batch_features.to(device)
        outputs = autoencoder(batch_features)
        loss = criterion(outputs, batch_features)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item()
    avg_loss = epoch_loss / len(train_loader)
    scheduler.step()

    with torch.no_grad():
        val_loss = 0
        for batch_features, _ in val_loader:
            batch_features = batch_features.to(device)
            outputs = autoencoder(batch_features)
            loss = criterion(outputs, batch_features)
            val_loss += loss.item()
        avg_val_loss = val_loss / len(val_loader)
        print(f'Epoch {epoch + 1}/{epochs}, Train Loss: {avg_loss:.6f}, Val Loss: {avg_val_loss:.6f}')

        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            epochs_without_improvement = 0
            best_model_state_dict = autoencoder.state_dict()
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= patience:
                print(f"Early stopping triggered after {epoch + 1} epochs.")
                break

#Threshold calculation (using training data) MUST BE BEFORE predicted_labels
#Threshold calculation (using training data) MUST BE BEFORE predicted_labels
reconstruction_errors_train = []
with torch.no_grad():
    for batch_features, _ in train_loader:
        batch_features = batch_features.to(device)
        outputs = autoencoder(batch_features)
        loss = criterion(outputs, batch_features)
        reconstruction_errors_train.extend(loss.cpu().numpy())

mean_loss_train = np.mean(reconstruction_errors_train)
std_loss_train = np.std(reconstruction_errors_train)
threshold = mean_loss_train + 3 * std_loss_train

#Testing and Visualization
autoencoder.load_state_dict(best_model_state_dict)
autoencoder.eval()
reconstruction_errors_test = []
true_labels_test = []

with torch.no_grad():
    for i, (batch_features, batch_labels) in enumerate(test_loader):
        batch_features = batch_features.to(device)
        outputs = autoencoder(batch_features)
        loss = criterion(outputs, batch_features)
        reconstruction_errors_test.extend(loss.cpu().numpy())
        true_labels_test.extend(batch_labels.cpu().numpy()) 

print(f"Length of reconstruction_errors_test: {len(reconstruction_errors_test)}")
print(f"Length of true_labels_test: {len(true_labels_test)}")

predicted_labels = np.array(reconstruction_errors_test) > threshold

# Classify and evaluate
fpr, tpr, _ = roc_curve(true_labels_test, predicted_labels)
roc_auc = auc(fpr, tpr)
precision, recall, _ = precision_recall_curve(true_labels_test, predicted_labels)

# Create visualizations
plt.figure(figsize=(12, 4))

plt.subplot(1, 3, 1)
sns.histplot(reconstruction_errors_test, kde=True)
plt.axvline(threshold, color='r', linestyle='--', label=f'Threshold: {threshold:.4f}')
plt.title('Reconstruction Error Distribution')
plt.legend()

plt.subplot(1, 3, 2)
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend(loc="lower right")

plt.subplot(1, 3, 3)
plt.plot(recall, precision, color='darkorange', lw=2, label='Precision-Recall Curve')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('Recall')
plt.ylabel('Precision')
plt.title('Precision-Recall Curve')
plt.legend(loc="lower left")

plt.tight_layout()
plt.show()


# Save model and scaler
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
model_path = f'./enhanced_autoencoder_model_best_{timestamp}.pth'
scaler_path = f'./scaler_{timestamp}.joblib'

torch.save(autoencoder.state_dict(), model_path)
joblib.dump(scaler, scaler_path)

print(f"Model saved to {model_path}")
print(f"Scaler saved to {scaler_path}")