import pandas as pd
import re
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from sentence_transformers import SentenceTransformer

# ... (parse_log_line function remains the same) ...
def parse_log_line(line):
    log_pattern = re.compile(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w-]+)\s+([\w]+)\[(\d+)\]:\s+(.*)')
    match = log_pattern.match(line)
    if match:
        timestamp_str, hostname, process, pid, message = match.groups()
        return {'process': process, 'message': message.strip()}
    return None

def main():
    log_file_path = 'data/normal_traffic.log'
    print("Starting anomaly detector training with scaling...")
    
    with open(log_file_path, 'r') as f: lines = f.readlines()
    parsed_logs = [parse_log_line(line) for line in lines if parse_log_line(line)]
    df = pd.DataFrame(parsed_logs)
    
    print("Performing feature engineering...")
    
    embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    message_embeddings = embedding_model.encode(df['message'].tolist(), show_progress_bar=True)
    message_features_df = pd.DataFrame(message_embeddings)

    df['msg_length'] = df['message'].str.len()
    df['special_chars'] = df['message'].apply(lambda x: len(re.findall(r'[^a-zA-Z0-9\s]', x)))
    structural_features = df[['msg_length', 'special_chars']]
    process_features = pd.get_dummies(df['process'], prefix='proc')
    
    features = pd.concat([structural_features.reset_index(drop=True), message_features_df.reset_index(drop=True), process_features.reset_index(drop=True)], axis=1)
    features.columns = features.columns.astype(str)
    
    # --- NEW: Scale the features ---
    print("Scaling features...")
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    print(f"Created scaled feature matrix with shape: {features_scaled.shape}")

    print("Training the Isolation Forest model...")
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(features_scaled)
    
    # --- Save the scaler along with other artifacts ---
    joblib.dump(model, 'models/isolation_forest_model.joblib')
    joblib.dump(scaler, 'models/scaler.joblib') # <-- SAVE THE SCALER
    joblib.dump(features.columns.tolist(), 'models/feature_columns.joblib')
    
    print("\nModel, scaler, and feature columns saved successfully.")

if __name__ == "__main__":
    main()