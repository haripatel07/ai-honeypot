# Generative AI-Driven Honeypot

This project is a sophisticated cybersecurity honeypot that uses a two-part AI system to detect intruders. It first generates a realistic but synthetic "normal" environment and then uses an unsupervised anomaly detection model to spot any activity that deviates from that norm.

The project demonstrates a realistic, iterative machine learning workflow, including advanced feature engineering, model tuning, and debugging.

---
## Demo

A live simulation of the honeypot detecting a malicious log entry injected into a stream of normal, AI-generated traffic.

![Demo](https://github.com/haripatel07/ai-honeypot/blob/main/pictures/demo.png)
---
## Key Features

- **Synthetic Data Generation**: A procedural generator creates thousands of realistic syslog entries to simulate a normal server environment, providing a clean baseline for model training.
- **Unsupervised Anomaly Detection**: An `IsolationForest` model is trained to learn the patterns of the normal data. This approach is powerful because it can detect novel attacks without needing prior examples of malicious activity.
- **State-of-the-Art Feature Engineering**:
    - **Sentence Embeddings**: Uses a pre-trained **Sentence Transformer** model (`all-MiniLM-L6-v2`) to convert log messages into semantic vectors, allowing the model to understand the *meaning* of the text, not just the words.
    - **Structural Features**: Captures metadata like message length and special character counts to identify structural outliers.
    - **Feature Scaling**: Implements `StandardScaler` to normalize the feature set, ensuring all features contribute equally to the model's decisions—a critical MLOps best practice.

---
## Tech Stack

- **Primary Language**: Python
- **Machine Learning**: Scikit-learn, Pandas, NumPy
- **Natural Language Processing**: Sentence-Transformers (Hugging Face)
- **Tooling**: Joblib

---

## Project Structure

The repository is organized as follows:

```
├── data/               # Contains the generated synthetic log data.
├── models/             # Stores the trained ML models and helper artifacts (.joblib).
├── pictures/           # For storing screenshots and demo GIFs for the README.
├── src/                # All Python source code.
│   ├── data_generator/   # Script to generate synthetic log files.
│   └── anomaly_detector/ # Script to train the anomaly detection model.
├── venv/               # Python virtual environment (ignored by Git).
├── .gitignore          # Specifies files and directories for Git to ignore.
├── honeypot_app.py     # The main application script to run the simulation.
├── LICENSE             # The project's MIT License.
├── live_honeypot.log   # The simulated log file generated at runtime (ignored).
├── README.md           # This documentation file.
└── requirements.txt    # A list of Python packages required for the project.
```
---
## How to Run

Follow these instructions to set up and run the project locally.

### 1. Clone the Repository
```bash
git clone [https://github.com/haripatel07/ai-honeypot.git](https://github.com/haripatel07/ai-honeypot.git)
cd ai-honeypot
```

### 2. Set Up the Environment
```bash
# Create and activate a virtual environment
python -m venv venv
# On Windows: venv\Scripts\activate
# On macOS/Linux: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Full Pipeline
The project runs in three stages. Run these commands in order from the root directory.

**Stage 1: Generate the baseline log data.**
```bash
python src/data_generator/generate_logs.py
```

**Stage 2: Train the anomaly detection model.**
*(Note: The first time you run this, it will download the pre-trained Sentence Transformer model, which is a few hundred MB).*
```bash
python src/anomaly_detector/train_detector.py
```
This creates the necessary model files in the `models/` directory, which are ignored by Git.

**Stage 3: Run the live honeypot simulation.**
```bash
python honeypot_app.py
```
Watch the terminal to see the stream of normal logs followed by the detection of an injected malicious log.

---
## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.