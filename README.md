# SentinelSphere

**Cloud-Based Proactive Threat Shield — Powered by ML, NLP & Graph Intelligence**

## 🛡️ Overview

SentinelSphere is a proactive cybersecurity platform that detects phishing links, malicious emails, and QR code scams **before** users interact with them. Unlike traditional reactive systems that rely on blacklists and signatures, SentinelSphere uses machine learning, natural language processing, rule-based heuristics, and graph intelligence to predict zero-day threats — and explains *why* something is dangerous.

## ✨ Features

- **URL Scanning** – ML-powered threat detection with Logistic Regression
- **Email Scanning** – NLP-based phishing analysis with Naive Bayes
- **QR Code Scanning** – Decode and analyze embedded URLs
- **Bulk Scanning** – Scan multiple URLs in batch mode
- **Graph Intelligence** – Track relationships between users, domains, and IPs
- **Risk Engine** – Weighted scoring combining ML, reputation, graph, and rule-based signals
- **Explainable AI** – Shows exactly *why* a threat was flagged
- **Real-time Analytics** – Donut charts, trend bars, live threat feed
- **Firebase Cloud Storage** – Real-time persistence with Firestore

## 🏗️ Architecture

```
User → Firebase Hosting (Static Site) → Client-side Threat Engine → Firebase Firestore
```

```
┌─────────────────────────────────────────────────────┐
│                   FRONTEND (Browser)                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │URL Scanner│ │Email Scan│ │ QR Scan  │ │  Bulk  │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘ │
│       └─────────────┼───────────┘            │      │
│              ┌──────▼──────┐                 │      │
│              │ Threat Engine│◄────────────────┘      │
│              │ (Client JS) │                        │
│              └──────┬──────┘                        │
│       ┌─────────────┼─────────────┐                 │
│  ┌────▼────┐ ┌──────▼─────┐ ┌────▼─────┐           │
│  │ML Scorer│ │Rule Engine │ │Graph Eng.│           │
│  └────┬────┘ └──────┬─────┘ └────┬─────┘           │
│       └─────────────┼────────────┘                  │
│              ┌──────▼──────┐                        │
│              │ Risk Engine │                        │
│              └──────┬──────┘                        │
│                     │                               │
│              ┌──────▼──────┐                        │
│              │ Dashboard   │                        │
│              │ (D3.js)     │                        │
│              └─────────────┘                        │
└──────────────────────┬──────────────────────────────┘
                       │ Firebase JS SDK
              ┌────────▼────────┐
              │ Firebase Cloud  │
              │  ┌────────────┐ │
              │  │ Firestore  │ │
              │  │ - reports  │ │
              │  │ - nodes    │ │
              │  │ - edges    │ │
              │  └────────────┘ │
              └─────────────────┘
```

## 🔧 Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **Visualization** | D3.js (force-directed graph) |
| **ML Engine** | Custom Logistic Regression & Naive Bayes (client-side JS) |
| **Database** | Google Firebase Firestore |
| **Hosting** | Firebase Hosting |
| **Analytics** | Firebase Analytics |

## 🚀 Quick Start

### Local Testing
```bash
# Simply open in any browser — works fully standalone
open index.html

# Or use a local server
python -m http.server 8000
# Visit http://localhost:8000
```

### Firebase Deployment
```bash
# Install Firebase CLI
npm install -g firebase-tools

# Login to Firebase
firebase login

# Deploy to Firebase Hosting
firebase deploy
```

**Live URL after deployment:** `https://pbl-4th-sem.web.app`

### Firebase Setup (One-time)
1. Go to [Firebase Console](https://console.firebase.google.com)
2. Open the `pbl-4th-sem` project
3. Enable **Firestore Database** (Native mode)
4. Go to **Firestore → Rules** tab and paste:
   ```
   rules_version = '2';
   service cloud.firestore {
     match /databases/{database}/documents {
       match /{document=**} {
         allow read, write: if true;
       }
     }
   }
   ```
5. Click **Publish**

## 📂 Project Structure

```
SentinelSphere/
├── index.html              # Dashboard UI
├── enhanced.css            # Styling
├── app.js                  # Core app logic + threat engine
├── firebase-config.js      # Firebase SDK initialization + Firestore helpers
├── graph_visualization.js  # D3.js graph visualization
├── enhanced-features.js    # Analytics, bulk scan, exports, shortcuts
├── firebase.json           # Firebase Hosting config
├── firestore.rules         # Firestore security rules
├── firestore.indexes.json  # Firestore indexes
├── backend/                # Python reference implementations
│   ├── handlers/           # Scan handlers (URL, Email, QR)
│   ├── threat_modules/     # URL, Email analyzers, QR decoder
│   ├── graph_engine/       # Graph builder & metrics
│   ├── risk_engine/        # Risk calculator
│   └── utils/              # Firebase client & helpers
└── infrastructure/         # Deployment documentation
```

## 🔥 Firebase Collections

| Collection | Purpose | Key Fields |
|---|---|---|
| `threat_reports` | All scan reports | `report_id`, `input_type`, `risk_score`, `risk_level`, `timestamp` |
| `graph_nodes` | Graph entities | `node_id`, `node_type`, `label`, `scan_count` |
| `graph_edges` | Relationships | `source_node`, `target_node`, `relation_type`, `occurrence_count` |

## 📊 Scoring System

The risk score (0.0 – 1.0) is calculated by combining four weighted signals:

| Signal | Weight | Source |
|---|---|---|
| ML Score | 35% | Logistic Regression (URL) / Naive Bayes (Email) |
| Reputation Score | 25% | Domain age, TLD analysis, known patterns |
| Graph Score | 20% | Frequency + Centrality + Burst detection |
| Rule-based Score | 20% | Heuristic pattern matching |

## 👥 Team

PBL 4th Semester Project — SentinelSphere Team
