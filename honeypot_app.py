import joblib
import pandas as pd
import time
import random
import re

# Import the parsing function from your training script
from src.anomaly_detector.train_detector import parse_log_line

# --- Load the Trained Model, Vectorizer, and Feature Columns ---
try:
    model = joblib.load('models/isolation_forest_model.joblib')
    vectorizer = joblib.load('models/tfidf_vectorizer.joblib')
    reference_cols = joblib.load('models/feature_columns.joblib')
except FileNotFoundError:
    print("ERROR: Model files not found. Please run train_detector.py first.")
    exit()

# --- Define Anomalous/Malicious Log Entries for Simulation ---
malicious_logs = [
    "Sep 02 21:40:00 corp-server-01 sshd[9999]: Failed password for invalid user evil from 172.16.0.100 port 22",
    "Sep 02 21:41:00 web-prod-03 kernel: [9999]: Buffer overflow attempt detected from 10.0.5.20",
    "Sep 02 21:42:00 db-main-01 mysql[1111]: SQL injection attempt: ' or 1=1; --",
    "Sep 02 21:43:00 api-gateway-1 sudo[4321]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/nmap -sS 10.0.0.0/24"
]

# ... (all the code at the top of the file remains the same) ...

def process_log_entry(log_line):
    """Processes a new log line and predicts if it's an anomaly."""
    parsed = parse_log_line(log_line)
    if not parsed:
        return 1

    df_new = pd.DataFrame([parsed])
    df_new['msg_length'] = df_new['message'].str.len()
    df_new['special_chars'] = df_new['message'].apply(lambda x: len(re.findall(r'[^a-zA-Z0-9\s]', x)))

    message_features_df = pd.DataFrame(
        vectorizer.transform(df_new['message']).toarray(),
        columns=vectorizer.get_feature_names_out()
    )

    # --- THE FIX IS HERE ---
    # Add the same prefix used during training
    process_features_df = pd.get_dummies(df_new['process'], prefix='proc')

    structural_features = df_new[['msg_length', 'special_chars']]
    new_log_features_df = pd.concat([structural_features, message_features_df, process_features_df], axis=1)
    
    final_features = new_log_features_df.reindex(columns=reference_cols, fill_value=0)
    
    prediction = model.predict(final_features)
    return prediction[0]

# ... (the main() function and the rest of the file remain the same) ...

def main():
    """Main simulation loop for the honeypot."""
    live_log_file = 'live_honeypot.log'
    print(f"🍯 Honeypot is now live. Running a SHORT test simulation...")
    print("Press Ctrl+C to stop.")

    try:
        with open('data/normal_traffic.log', 'r') as f:
            # Only use the first 30 lines for a quick test
            normal_lines = f.readlines()[:30]
        
        # Set a fixed injection point
        injection_point = 15
        
        with open(live_log_file, 'w') as live_log:
            for i, line in enumerate(normal_lines):
                # Inject a malicious log at the specified point
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

                # Write and analyze a normal log line
                live_log.write(line)
                live_log.flush()
                
                prediction = process_log_entry(line)
                if prediction == 1:
                    print(f"🟢 STATUS: Normal -> {line.strip()}")
                else:
                    print(f"🟡 \033[93mWARNING: A normal log was flagged as an anomaly (False Positive).\033[0m")
                time.sleep(0.2) # Faster for testing

    except KeyboardInterrupt:
        print("\nHoneypot simulation stopped.")

if __name__ == "__main__":
    main()
