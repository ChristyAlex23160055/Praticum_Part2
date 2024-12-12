# Praticum_Part2
Repository for Anomaly detection project part of Praticum part2
Project Overview

This repository contains a machine learning-based network anomaly detection system. It leverages an autoencoder to identify anomalies in network traffic based on reconstruction errors. The project includes tools for data collection, preprocessing, and model training, designed for both synthetic and live network environments.

**Getting Started**

Follow these steps to set up and run the project:

**1. Clone the Repository**

git clone <repository-url>
cd <repository-name>

**2. Install Dependencies**

Ensure you have Python installed. Install the required packages using:

pip install -r requirements.txt

**3. Collect Training Data**

Run the script suracataIntegration.py to collect network traffic data for training:

python suracataIntegration.py

This script uses Suricata to capture packets and convert them into a CSV format for training.

**4. Train the Model**

Before running the training script, update the file paths in encoder6.py to point to your collected dataset. Then execute:

python encoder6.py

This script trains the autoencoder model and saves the results for further analysis.

**Project Structure**

suracataIntegration.py: Script for capturing live network traffic using Suricata.

encoder6.py: Script for training the autoencoder and evaluating its performance.

requirements.txt: List of required Python packages.

data/: Directory to store collected datasets.

models/: Directory for saving trained models.

Features

Data collection from live traffic using Suricata.

Preprocessing of network traffic data for machine learning.

Anomaly detection using autoencoder reconstruction errors.

Results and Analysis

The trained model's performance is evaluated using:

ROC Curve: Visualizes the trade-off between sensitivity and specificity.

Precision-Recall Curve: Highlights model precision and recall for different thresholds.

Future Work

Potential improvements and extensions include:

Implementing adaptive thresholding for anomaly detection.

Exploring alternative architectures like variational autoencoders.

Collecting more diverse datasets to enhance model generalization.

Contributions

Feel free to fork this repository and submit pull requests for any improvements or bug fixes.

License

This project is licensed under the MIT License.

Contact

For questions or collaboration opportunities, contact [Christy Alex] at [x23160055@student.ncirl.ie].
