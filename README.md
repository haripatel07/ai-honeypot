# Generative AI-Driven Honeypot

![Status](https://img.shields.io/badge/status-in%20development-yellow)

This project is an advanced cybersecurity tool that uses a generative AI model to create a convincing honeypot, and a separate anomaly detection model to identify intruders.

## Core Concepts
1.  **Generative AI for Deception:** A model will be trained to produce realistic-looking (but fake) system log data, creating a high-fidelity decoy for attackers.
2.  **Anomaly Detection for Security:** An unsupervised machine learning model will learn the patterns of the fake data and immediately flag any interaction that deviates from the norm, indicating a potential breach.

## Planned Tech Stack
- **Backend**: Python
- **Generative Model**: (To be determined: e.g., Markov Chains, RNN, or a small Transformer)
- **Anomaly Detection**: Scikit-learn (e.g., Isolation Forest, Autoencoder)
- **Containerization**: Docker

## Project Status
This project is currently in the initial setup phase. The next step is to develop the data generation module.