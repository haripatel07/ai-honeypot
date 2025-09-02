import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
import joblib

def parse_log_line(line):
    # This function remains the same
    log_pattern = re.compile(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w-]+)\s+([\w]+)\[(\d+)\]:\s+(.*)')
    match = log_pattern.match(line)
    if match:
        timestamp_str, hostname, process, pid, message = match.groups()
        return {
            'timestamp': pd.to_datetime(timestamp_str, format='%b %d %H:%M:%S'),
            'hostname': hostname,
            'process': process,
            'message': message.strip()
        }
    return None

def main():
    log_file_path = 'data/normal_traffic.log'
    print("Starting anomaly detector training...")
    
    with open(log_file_path, 'r') as f:
        lines = f.readlines()
    
    parsed_logs = [parse_log_line(line) for line in lines if parse_log_line(line)]
    df = pd.DataFrame(parsed_logs)
    
    print("Performing feature engineering with structural features...")
    
    df['msg_length'] = df['message'].str.len()
    df['special_chars'] = df['message'].apply(lambda x: len(re.findall(r'[^a-zA-Z0-9\s]', x)))
    
    vectorizer = TfidfVectorizer(max_features=100)
    message_features = vectorizer.fit_transform(df['message']).toarray()
    message_features_df = pd.DataFrame(message_features, columns=vectorizer.get_feature_names_out())

    # --- THE FIX IS HERE ---
    # Add a prefix to avoid column name collisions
    process_features = pd.get_dummies(df['process'], prefix='proc')
    
    structural_features = df[['msg_length', 'special_chars']]
    features = pd.concat([structural_features.reset_index(drop=True), message_features_df, process_features.reset_index(drop=True)], axis=1)
    features.columns = features.columns.astype(str)
    
    print(f"Created feature matrix with shape: {features.shape}")

    print("Training the Isolation Forest model...")
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(features)
    
    joblib.dump(model, 'models/isolation_forest_model.joblib')
    joblib.dump(vectorizer, 'models/tfidf_vectorizer.joblib')
    joblib.dump(features.columns.tolist(), 'models/feature_columns.joblib')
    
    print("\nModel, vectorizer, and feature columns saved successfully.")
    print("Training complete!")

if __name__ == "__main__":
    main()