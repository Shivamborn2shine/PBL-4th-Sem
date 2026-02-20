# SentinelSphere

Cloud-Based Proactive Threat Shield – Serverless AWS Application

## Features
- **URL Scanning** – ML-powered threat detection with Logistic Regression
- **Email Scanning** – NLP-based phishing analysis with Naive Bayes
- **QR Code Scanning** – Decode and analyze embedded URLs
- **Graph Intelligence** – Track relationships between users, domains, and IPs
- **Risk Engine** – Weighted scoring combining ML, reputation, graph, and rule-based signals

## Architecture
```
User → Frontend (S3) → API Gateway → Lambda → Threat Modules → Graph Engine → Risk Engine → DynamoDB
```

## Tech Stack
- **Backend**: Python 3.11, AWS Lambda, DynamoDB, API Gateway
- **Frontend**: HTML/CSS/JS, D3.js for graph visualization
- **ML**: Custom Logistic Regression & Naive Bayes (no scikit-learn dependency)
- **Infrastructure**: AWS SAM (template.yaml)

## Quick Start

### Local Testing
Open `frontend/index.html` in any browser – runs fully standalone in mock mode.

### AWS Deployment
```bash
cd infrastructure
sam build
sam deploy --guided
```
Then update `CONFIG.API_BASE_URL` in `frontend/app.js` with your API Gateway URL.

## Project Structure
```
sentinelsphere/
├── backend/
│   ├── handlers/          # Lambda functions
│   ├── threat_modules/    # URL, Email, QR analyzers
│   ├── graph_engine/      # Graph builder & metrics
│   ├── risk_engine/       # Risk calculator
│   └── utils/             # Feature extraction & ML models
├── frontend/              # Dashboard UI
└── infrastructure/        # SAM template
```
