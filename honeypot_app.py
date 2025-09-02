import joblib
import pandas as pd
import time
import random
import re
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import StandardScaler # <-- Import StandardScaler

# Import the parsing function
from src.anomaly_detector.train_detector import parse_log_line

# --- Load Model, Scaler, Columns, and Sentence Transformer ---
try:
    model = joblib.load('models/isolation_forest_model.joblib')
    scaler = joblib.load('models/scaler.joblib') # <-- LOAD THE SCALER
    reference_cols = joblib.load('models/feature_columns.joblib')
    print("Loading sentence transformer model...")
    embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
except FileNotFoundError:
    print("ERROR: Model files not found. Please run the updated train_detector.py first.")
    exit()

# ... (malicious_logs list remains the same) ...
malicious_logs = [
    "Sep 02 21:40:00 corp-server-01 sshd[9999]: Failed password for invalid user evil from 172.16.0.100 port 22",
    "Sep 02 21:41:00 web-prod-03 kernel: [9999]: Buffer overflow attempt detected from 10.0.5.20",
    "Sep 02 21:42:00 db-main-01 mysql[1111]: SQL injection attempt: ' or 1=1; --"
]

def process_log_entry(log_line):
    """Processes a new log line and predicts if it's an anomaly."""
    parsed = parse_log_line(log_line)
    if not parsed: return 1

    df_new = pd.DataFrame([parsed])
    
    message_embedding = embedding_model.encode([df_new['message'].iloc[0]])
    message_features_df = pd.DataFrame(message_embedding)

    df_new['msg_length'] = df_new['message'].str.len()
    df_new['special_chars'] = df_new['message'].apply(lambda x: len(re.findall(r'[^a-zA-Z0-9\s]', x)))
    structural_features = df_new[['msg_length', 'special_chars']]

    process_features_df = pd.get_dummies(df_new['process'], prefix='proc')

    new_log_features_df = pd.concat([structural_features.reset_index(drop=True), message_features_df, process_features_df.reset_index(drop=True)], axis=1)
    new_log_features_df.columns = new_log_features_df.columns.astype(str)
    
    final_features = new_log_features_df.reindex(columns=reference_cols, fill_value=0)
    
    # --- NEW: Scale the features before prediction ---
    final_features_scaled = scaler.transform(final_features)
    
    # Prediction
    prediction = model.predict(final_features_scaled)
    return prediction[0]

# ... (main function remains the same) ...
def main():
    """Main simulation loop for the honeypot."""
    live_log_file = 'live_honeypot.log'
    print(f"🍯 Honeypot is now live. Running a SHORT test simulation...")
    print("Press Ctrl+C to stop.")

    try:
        with open('data/normal_traffic.log', 'r') as f:
            normal_lines = f.readlines()[:30]
        
        injection_point = 15
        
        with open(live_log_file, 'w') as live_log:
            for i, line in enumerate(normal_lines):
                if i == injection_point:
                    malicious_line = random.choice(malicious_logs)
                    live_log.write(malicious_line + '\n')
                    live_log.flush()
                    print("-" * 50)
                    print(f"Injecting malicious entry: {malicious_line.strip()}")
                    
                    prediction = process_log_entry(malicious_line)
                    if prediction == -1:
                        print("🔴 \033[91mSUCCESS: Anomaly correctly detected!\033[0m")
                    else:
                        print("🟡 \033[93mFAILURE: Malicious injection was NOT detected.\033[0m")
                    print("-" * 50)
                    time.sleep(3)

                live_log.write(line)
                live_log.flush()
                
                prediction = process_log_entry(line)
                if prediction == 1:
                    print(f"🟢 STATUS: Normal -> {line.strip()}")
                else:
                    print(f"🟡 \033[93mWARNING: A normal log was flagged as an anomaly (False Positive).\033[0m")
                time.sleep(0.2)

    except KeyboardInterrupt:
        print("\nHoneypot simulation stopped.")

if __name__ == "__main__":
    main()