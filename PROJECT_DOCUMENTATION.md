# SentinelSphere Project Documentation

SentinelSphere is a cloud-ready proactive threat scanning system for URLs, email text, and QR code images. It provides a browser dashboard, calculates risk using multiple signals, explains why an input is safe or dangerous, visualizes relationships between users/domains/IPs/emails, and persists reports plus graph data in Firebase Firestore.

The project currently supports two execution styles:

1. Local/mock frontend mode: open `index.html` in a browser. Scans are simulated in JavaScript, and the UI can also sync history/graph data to Firestore if Firebase is enabled.
2. AWS Lambda API mode: deploy the backend with AWS SAM. API Gateway invokes Python Lambda handlers, the backend performs real feature extraction/scoring, and reports/graph data are stored in Firestore using the Firebase Admin SDK.

## 1. Project Goals

The project demonstrates a full security-analysis workflow:

- Accept URLs, email text, and QR code images from a dashboard UI.
- Extract useful security features from each input.
- Score the input using ML-style prediction, reputation checks, graph intelligence, and rule-based detection.
- Classify the result as `SAFE`, `SUSPICIOUS`, or `HIGH`.
- Explain the indicators that caused the score.
- Store reports and graph relationships in Firestore.
- Show scan history, analytics, exported reports, raw JSON, and a D3 relationship graph.

## 2. High-Level Architecture

```text
User
  -> Browser UI: index.html, enhanced.css, app.js
  -> Local mock scan OR API Gateway
  -> Lambda handler: scan_url.py, scan_email.py, scan_qr.py
  -> Threat modules: URL, email, QR, reputation
  -> Feature extraction and ML utilities
  -> Graph builder and graph metrics
  -> Risk calculator
  -> Firebase Firestore collections
  -> JSON response to browser
  -> Results panel, analytics, history, graph view
```

In local/mock mode, the browser uses JavaScript mock scanners. If `CONFIG.USE_FIREBASE` is true, the browser also writes mock scan results to Firestore through the Firebase Web SDK.

In AWS mode, the browser sends requests to API Gateway. Lambda runs the Python backend and stores data in Firestore through the Firebase Admin SDK.

## 3. Repository Structure

```text
.
|-- index.html
|-- enhanced.css
|-- app.js
|-- enhanced-features.js
|-- graph_visualization.js
|-- firebase-config.js
|-- README.md
|-- test_data.md
|-- PROJECT_DOCUMENTATION.md
|-- backend/
|   |-- requirements.txt
|   |-- handlers/
|   |   |-- scan_url.py
|   |   |-- scan_email.py
|   |   |-- scan_qr.py
|   |-- threat_modules/
|   |   |-- url_analyzer.py
|   |   |-- email_analyzer.py
|   |   |-- qr_decoder.py
|   |   |-- reputation_checker.py
|   |-- utils/
|   |   |-- feature_extractor.py
|   |   |-- ml_model.py
|   |   |-- firebase_client.py
|   |-- graph_engine/
|   |   |-- graph_builder.py
|   |   |-- graph_metrics.py
|   |-- risk_engine/
|       |-- risk_calculator.py
|-- infrastructure/
    |-- template.yaml
```

## 4. Technology Stack

Frontend:

- HTML, CSS, and vanilla JavaScript.
- D3.js for graph visualization.
- Firebase Web SDK in compat mode for browser-side Firestore access.
- Browser `localStorage` for local history/graph cache.

Backend:

- Python 3.11.
- AWS Lambda handlers behind API Gateway.
- Firebase Admin SDK for server-side Firestore access.
- Custom lightweight ML classes in Python.
- Feature extraction and rule-based scoring.

Cloud/infrastructure:

- AWS SAM for API Gateway and Lambda deployment.
- Firebase Firestore for report and graph persistence.

## 5. Frontend Documentation

### 5.1 `index.html`

`index.html` defines the full dashboard screen. It contains:

- Page metadata.
- Google Fonts import.
- D3.js CDN import.
- Firebase SDK scripts.
- Core inline design system CSS.
- Links to `enhanced.css`.
- Main HTML layout.
- Script imports for `firebase-config.js`, `app.js`, `graph_visualization.js`, and `enhanced-features.js`.

Major UI areas:

- Header with SentinelSphere brand, version, clock, and online status.
- Stats bar showing total scans, threats found, safe results, graph nodes, average risk, and last scan time.
- Analytics section with threat distribution and scan trend.
- Scan tabs: URL, Email, QR, Graph View, Bulk Scan, and History.
- Left-side scan input panels.
- Right-side results panel.
- Relationship graph panel.
- History table with search/filter controls.
- Live threat feed.
- Footer and keyboard shortcut hint.

### 5.2 `enhanced.css`

`enhanced.css` adds the polished UI layer:

- Particle canvas styling.
- Toast notifications.
- Header metadata styling.
- Six-column stats layout.
- Analytics cards and charts.
- Bulk scan progress/results styling.
- Result tabs and raw JSON panel.
- Export buttons.
- Threat feed ticker.
- History search/filter chips.
- Footer.
- Responsive overrides.
- Print styles.

### 5.3 `app.js`

`app.js` is the core frontend controller.

Important configuration:

```js
const CONFIG = {
    API_BASE_URL: '',
    MOCK_MODE: true,
    USE_FIREBASE: true,
};
```

Meaning:

- `API_BASE_URL`: API Gateway base URL after deployment.
- `MOCK_MODE`: when true, the browser uses mock scan functions instead of Lambda APIs.
- `USE_FIREBASE`: when true, the browser attempts to sync scan reports and graph data to Firestore.

Important state:

```js
const state = {
    history: JSON.parse(localStorage.getItem('sentinelsphere_history') || '[]'),
    graphData: JSON.parse(localStorage.getItem('sentinelsphere_graph') || '{"nodes":[],"edges":[]}'),
    stats: {
        totalScans: 0,
        threatsFound: 0,
        safeCount: 0,
    },
    currentQrBase64: null,
};
```

Frontend localStorage keys:

```text
sentinelsphere_history
sentinelsphere_graph
sentinelsphere_sessions
```

### 5.4 Tab Navigation

The tab system switches between panels:

- `url`: URL scanner.
- `email`: email phishing scanner.
- `qr`: QR image scanner.
- `bulk`: batch URL scanner.
- `graph`: D3 relationship graph.
- `history`: scan history table.

### 5.5 URL Scan Flow

Function: `scanUrl()`

Flow:

1. Read the target URL from `urlInput`.
2. Read optional `urlUserId`; default is `anonymous`.
3. Validate that a URL was entered.
4. Show button loading state.
5. If `MOCK_MODE` is true, call `mockScanUrl(url, userId)`.
6. If `MOCK_MODE` is false, POST to `${API_BASE_URL}/api/v1/scan-url`.
7. Render the response with `displayResults(result)`.
8. Save the result to history.
9. Update local graph data.
10. If Firebase is enabled, save the report and graph data to Firestore.

Request body in API mode:

```json
{
  "user_id": "anonymous",
  "url": "https://example.com"
}
```

### 5.6 Email Scan Flow

Function: `scanEmail()`

Flow:

1. Read email content from `emailInput`.
2. Read optional `emailUserId`; default is `anonymous`.
3. Validate that email text exists.
4. Use mock analysis or POST to `/api/v1/scan-email`.
5. Render the result.
6. Save a shortened input preview to history.
7. If Firebase is enabled, persist the report.

Request body in API mode:

```json
{
  "user_id": "anonymous",
  "email_text": "Raw email content"
}
```

### 5.7 QR Scan Flow

Functions:

- `handleQrUpload(event)`
- `scanQr()`

Flow:

1. User uploads or drags a QR image file.
2. `FileReader` converts the image to a base64 data URL.
3. The preview image is displayed.
4. The QR scan button is enabled.
5. `scanQr()` uses mock analysis or POSTs to `/api/v1/scan-qr`.
6. If a URL is extracted, the result is shown and graph/history are updated.

Request body in API mode:

```json
{
  "user_id": "anonymous",
  "image_base64": "data:image/png;base64,..."
}
```

### 5.8 Results Panel

Function: `displayResults(result)`

The results panel displays:

- Risk score gauge.
- Risk level badge.
- Score breakdown:
  - `ml_score`
  - `reputation_score`
  - `graph_score`
  - `rule_based_score`
- Human-readable threat indicators.

`enhanced-features.js` wraps this function to also:

- Store the latest result for export.
- Show raw JSON.
- Update analytics.
- Show toast notifications.

### 5.9 History

Function: `addToHistory(type, input, result)`

History entry shape:

```json
{
  "id": 1710000000000,
  "type": "URL",
  "input": "https://example.com",
  "risk_score": 0.42,
  "risk_level": "SUSPICIOUS",
  "timestamp": "local browser timestamp"
}
```

History is:

- Stored locally in `sentinelsphere_history`.
- Limited to the latest 50 browser entries.
- Optionally synced to Firestore when `CONFIG.USE_FIREBASE` is true.

Important security note: the current frontend includes functions that can clear all Firestore history/graph data if Firestore rules allow it. In production, do not expose global delete permissions to public clients.

### 5.10 Frontend Firestore Integration

File: `firebase-config.js`

This file:

- Defines the Firebase Web SDK config.
- Calls `firebase.initializeApp(firebaseConfig)`.
- Creates `db = firebase.firestore()`.
- Defines collection names.
- Provides helper functions for reports, graph nodes, and graph edges.

Collections:

```text
threat_reports
graph_nodes
graph_edges
```

Main browser helper functions:

- `firebaseSaveReport(report)`
- `firebaseLoadHistory(limit = 50)`
- `firebaseClearHistory()`
- `firebaseSaveGraphNode(nodeId, nodeType, label)`
- `firebaseSaveGraphEdge(source, target, relation)`
- `firebaseLoadGraphData()`
- `firebaseClearGraphData()`

Frontend Firebase notes:

- Firebase web API keys are not secret by themselves.
- Firestore security rules are the real security boundary.
- Do not use `allow read, write: if true` for a public production deployment.
- If this is only a classroom/demo app, keep rules temporary and restrict them before sharing publicly.

### 5.11 Graph Visualization

File: `graph_visualization.js`

The graph uses D3.js force simulation to show relationships.

Node types:

- `USER`
- `DOMAIN`
- `IP`
- `EMAIL`

Relationship types:

- `scanned`
- `resolves_to`
- `associated_with`

Features:

- Force-directed layout.
- Zoom and pan.
- Draggable nodes.
- Colored node types.
- Edge labels.
- Empty state when no graph data exists.

### 5.12 Enhanced Frontend Features

File: `enhanced-features.js`

Adds:

- Animated particle background.
- Header clock.
- Toast messages.
- Result tabs.
- JSON export.
- Text report copy.
- History export.
- History search/filter.
- Bulk URL scanning.
- Analytics donut chart.
- Scan trend bars.
- Mock live threat feed.
- Keyboard shortcuts:
  - `Ctrl + Enter`: scan active panel.
  - `Ctrl + E`: export latest report.

## 6. Backend Documentation

The backend is a Python Lambda codebase. It is split into handlers, threat modules, utility modules, graph modules, and the risk engine.

### 6.1 API Endpoints

Defined in `infrastructure/template.yaml`:

```text
POST /api/v1/scan-url
POST /api/v1/scan-email
POST /api/v1/scan-qr
OPTIONS for CORS preflight
```

All handlers return CORS headers:

```text
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Content-Type,X-Amz-Date,Authorization,X-Api-Key
Access-Control-Allow-Methods: POST,OPTIONS
```

### 6.2 URL Handler

File: `backend/handlers/scan_url.py`

Processing steps:

1. Parse the API Gateway event body.
2. Read `user_id` and `url`.
3. Validate that `url` is present.
4. Extract the domain from the URL.
5. Run `analyze_url(url)`.
6. Run `get_combined_reputation(domain)`.
7. Build Firestore graph data with `build_scan_graph(user_id, domain)`.
8. Compute graph suspicion with `compute_graph_suspicion(domain)`.
9. Fall back to offline graph scoring if graph scoring fails.
10. Calculate final risk with `calculate_risk(...)`.
11. Store the report in Firestore.
12. Return JSON to the frontend.

Response shape:

```json
{
  "report_id": "uuid",
  "risk_score": 0.72,
  "risk_level": "HIGH",
  "explanation": ["Suspicious keyword detected in URL"],
  "graph_suspicion": 0.21,
  "score_breakdown": {
    "ml_score": 0.81,
    "reputation_score": 0.45,
    "graph_score": 0.21,
    "rule_based_score": 0.65
  },
  "confidence": 0.83,
  "domain": "example.com",
  "timestamp": "2026-05-01T00:00:00+00:00"
}
```

### 6.3 Email Handler

File: `backend/handlers/scan_email.py`

Processing steps:

1. Parse `user_id` and `email_text`.
2. Validate that email text exists.
3. Run `analyze_email(email_text)`.
4. Attempt to extract a sender/domain-like value from the email text.
5. If a domain exists, run reputation checks and graph scoring.
6. Calculate final risk.
7. Store a Firestore report. The email input is truncated to 500 characters.
8. Return JSON.

Response shape:

```json
{
  "report_id": "uuid",
  "risk_score": 0.57,
  "risk_level": "SUSPICIOUS",
  "explanation": ["Urgency keyword detected"],
  "score_breakdown": {
    "ml_score": 0.70,
    "reputation_score": 0.10,
    "graph_score": 0.15,
    "rule_based_score": 0.45
  },
  "confidence": 0.75,
  "timestamp": "2026-05-01T00:00:00+00:00"
}
```

### 6.4 QR Handler

File: `backend/handlers/scan_qr.py`

Processing steps:

1. Parse `user_id` and `image_base64`.
2. Validate that image data exists.
3. Decode QR content with `decode_qr(image_base64)`.
4. Extract a URL from decoded content.
5. Run URL analysis, reputation, graph scoring, and risk scoring.
6. Store a Firestore report with input type `QR`.
7. Return standard scan fields plus QR-specific fields.

QR-specific response fields:

```json
{
  "extracted_url": "https://example.com",
  "qr_raw_data": "https://example.com"
}
```

## 7. Threat Analysis Modules

### 7.1 URL Analyzer

File: `backend/threat_modules/url_analyzer.py`

Main function:

```python
analyze_url(url: str) -> dict
```

It returns:

- `ml_score`
- `rule_based_score`
- `features`
- `explanations`

Rule-based URL scoring considers:

- Very young domain age.
- Missing HTTPS.
- IP address instead of domain name.
- `@` symbol.
- Suspicious keywords.
- Suspicious TLD.
- Long URL.
- Excessive subdomains.
- High entropy/randomness.
- Simulated IP reputation.

### 7.2 Email Analyzer

File: `backend/threat_modules/email_analyzer.py`

Main function:

```python
analyze_email(email_text: str) -> dict
```

Rule-based email scoring considers:

- Urgency keywords.
- Financial terms.
- Sender domain mismatch.
- Reply-To mismatch.
- Excessive exclamation marks.
- Multiple URLs.
- High uppercase ratio.
- Suspicious attachment language.

### 7.3 QR Decoder

File: `backend/threat_modules/qr_decoder.py`

Main function:

```python
decode_qr(image_base64: str) -> dict
```

It:

- Removes the data URL prefix if present.
- Base64-decodes the image.
- Attempts QR decoding with `pyzbar`.
- Falls back to PIL/numpy image inspection.
- Extracts a URL from decoded text.

Production note: reliable QR decoding in Lambda usually requires packaging `pyzbar` native dependencies or using a Lambda layer.

### 7.4 Reputation Checker

File: `backend/threat_modules/reputation_checker.py`

Main functions:

- `check_domain_reputation(domain)`
- `check_ip_reputation(ip)`
- `get_combined_reputation(domain, ip=None)`

The current implementation uses static lists and deterministic simulated lookups. For production, replace the simulated parts with services such as VirusTotal, AbuseIPDB, or Google Safe Browsing.

## 8. Feature Extraction

File: `backend/utils/feature_extractor.py`

URL features:

- `domain_age_days`
- `url_length`
- `num_dots`
- `contains_at`
- `contains_suspicious_words`
- `https_status`
- `ip_reputation_score`
- `num_subdomains`
- `has_ip_address`
- `path_length`
- `num_params`
- `suspicious_tld`
- `url_entropy`

Email features:

- `urgency_keywords_count`
- `financial_terms_count`
- `sender_domain_match`
- `reply_to_mismatch`
- `exclamation_frequency`
- `url_count`
- `email_length`
- `caps_ratio`
- `suspicious_attachment_mention`

Explanation helpers:

- `generate_url_explanations(features)`
- `generate_email_explanations(features)`

These explanations are shown directly in the UI.

## 9. Machine Learning Layer

File: `backend/utils/ml_model.py`

The project uses custom lightweight ML classes:

- `SimpleLogisticRegression` for URL threat prediction.
- `SimpleNaiveBayes` for email phishing prediction.

The models are trained from synthetic data at runtime and cached in module-level variables:

- `_URL_MODEL_CACHE`
- `_EMAIL_MODEL_CACHE`

Important dependency note: `ml_model.py` imports `numpy`, so `numpy` must be included in backend deployment dependencies.

## 10. Risk Engine

File: `backend/risk_engine/risk_calculator.py`

Final score formula:

```text
final_score =
    (ml_score * 0.4) +
    (reputation_score * 0.2) +
    (graph_score * 0.2) +
    (rule_based_score * 0.2)
```

Weights:

```json
{
  "ml_score": 0.4,
  "reputation_score": 0.2,
  "graph_score": 0.2,
  "rule_based_score": 0.2
}
```

Risk thresholds:

```text
0.0 <= score < 0.3  -> SAFE
0.3 <= score < 0.6  -> SUSPICIOUS
0.6 <= score <= 1.0 -> HIGH
```

Confidence is computed from how closely the individual signal scores agree with one another.

## 11. Firebase/Firestore Backend Storage

### 11.1 Firebase Admin Client

File: `backend/utils/firebase_client.py`

This module initializes Firebase Admin SDK and exposes collection helpers.

Credential loading order:

1. `GOOGLE_APPLICATION_CREDENTIALS`: path to a service account JSON file.
2. `FIREBASE_CREDENTIALS_JSON`: full service account JSON stored in an environment variable.
3. Default application credentials.

Backend collection helpers:

- `get_reports_collection()`
- `get_nodes_collection()`
- `get_edges_collection()`

Collection names are configurable with:

```text
THREAT_REPORTS_COLLECTION
GRAPH_NODES_COLLECTION
GRAPH_EDGES_COLLECTION
```

### 11.2 Firestore Collections

Collection: `threat_reports`

Purpose: Stores scan reports from URL, email, and QR scans.

Typical fields:

- `report_id`
- `user_id`
- `input_type`
- `input_value`
- `risk_score`
- `risk_level`
- `explanation`
- `timestamp`
- `score_breakdown`

Collection: `graph_nodes`

Purpose: Stores graph entities.

Typical fields:

- `node_id`
- `node_type`
- `metadata`
- `created_at`
- `updated_at`
- `scan_count`

Collection: `graph_edges`

Purpose: Stores graph relationships.

Typical fields:

- `source_node`
- `target_node`
- `relation_type`
- `weight`
- `timestamp`
- `occurrence_count`

### 11.3 Frontend and Backend Both Write to Firestore

Current behavior:

- In mock mode, the frontend writes mock scan reports to Firestore.
- In API mode, the backend writes real scan reports to Firestore.
- The frontend still calls `addToHistory()`, which may also write the backend response to Firestore if `USE_FIREBASE` is true.

Recommended production behavior:

- If `MOCK_MODE` is false, let the backend be the source of truth for Firestore writes.
- Avoid overwriting backend-created report documents from the frontend.
- Keep browser `localStorage` as a UI cache only.

## 12. Graph Intelligence

### 12.1 Graph Builder

File: `backend/graph_engine/graph_builder.py`

Main function:

```python
build_scan_graph(user_id: str, domain: str, ip: str = None, email: str = None)
```

It creates graph nodes:

- `user:{user_id}`
- `domain:{domain}`
- `ip:{ip}` if provided
- `email:{email}` if provided

It creates graph edges:

- User -> Domain with relation `scanned`.
- Domain -> IP with relation `resolves_to`.
- Email -> Domain with relation `associated_with`.

Firestore document IDs are sanitized by replacing `/` and `.` with `_`.

### 12.2 Graph Metrics

File: `backend/graph_engine/graph_metrics.py`

Metrics:

- `compute_frequency_score(domain)`: how often the domain appears.
- `compute_centrality_score(node_id)`: how connected the node is.
- `compute_burst_score(domain)`: how many recent reports include the domain.
- `compute_graph_suspicion(domain)`: average of the three scores.
- `compute_graph_suspicion_offline(domain)`: fallback when Firestore is unavailable.

Formula:

```text
graph_score = (frequency_score + centrality_score + burst_score) / 3
```

## 13. Infrastructure

File: `infrastructure/template.yaml`

Defined resources:

- `SentinelSphereApi`
- `ScanUrlFunction`
- `ScanEmailFunction`
- `ScanQrFunction`

Lambda global settings:

- Runtime: `python3.11`
- Timeout: 30 seconds
- Memory: 256 MB

Environment variables currently included:

```text
FIREBASE_PROJECT_ID=pbl-4th-sem
THREAT_REPORTS_COLLECTION=threat_reports
GRAPH_NODES_COLLECTION=graph_nodes
GRAPH_EDGES_COLLECTION=graph_edges
```

Required but not fully represented in the template:

- Firebase service account credentials through `GOOGLE_APPLICATION_CREDENTIALS` or `FIREBASE_CREDENTIALS_JSON`.

For AWS Lambda, a practical setup is:

1. Store the Firebase service account JSON in AWS Secrets Manager or as a protected environment variable.
2. Expose it to Lambda as `FIREBASE_CREDENTIALS_JSON`.
3. Update `firebase_client.py` or the SAM template as needed for secure loading.

## 14. Backend Dependencies

Current code imports require more than only Firebase packages.

Minimum backend dependencies for the current code path:

```text
firebase-admin>=6.0.0
google-cloud-firestore>=2.0.0
numpy>=1.24.0
Pillow>=10.0.0
pyzbar>=0.1.9
```

Notes:

- `numpy` is required by `backend/utils/ml_model.py`.
- `Pillow` and `pyzbar` are used by QR decoding.
- `pyzbar` can need native `zbar` support in the Lambda environment.
- If QR decoding is not needed in backend deployment, QR dependencies can be handled separately.

## 15. Local Usage

### 15.1 Run the UI in Mock Mode

1. Open `index.html` in a browser.
2. Keep `CONFIG.MOCK_MODE` set to `true`.
3. Use samples from `test_data.md`.

If `CONFIG.USE_FIREBASE` is true, the browser also needs:

- Internet access to Firebase CDN scripts.
- Valid Firebase config in `firebase-config.js`.
- Firestore rules that allow the intended reads/writes.

For a fully offline UI demo, set:

```js
USE_FIREBASE: false
```

### 15.2 Run Backend Handlers Locally

To test backend handlers locally, install backend requirements first. Then call handlers with API Gateway-like events.

Example URL handler event:

```json
{
  "httpMethod": "POST",
  "body": "{\"user_id\":\"demo\",\"url\":\"https://google.com\"}"
}
```

Without Firebase credentials, graph/report writes may fail or fall back, depending on where the failure happens.

## 16. AWS Deployment

From the project root:

```bash
cd infrastructure
sam build
sam deploy --guided
```

After deployment:

1. Copy the `ApiUrl` output.
2. Open `app.js`.
3. Set:

```js
const CONFIG = {
    API_BASE_URL: 'https://your-api-id.execute-api.your-region.amazonaws.com/prod',
    MOCK_MODE: false,
    USE_FIREBASE: true,
};
```

4. Configure Firebase Admin credentials for Lambda.
5. Test `/api/v1/scan-url`, `/api/v1/scan-email`, and `/api/v1/scan-qr`.

## 17. Testing Guide

Use `test_data.md` for manual tests.

Safe URL examples:

- `https://www.google.com`
- `https://github.com/Shivamborn2shine/PBL-4th-Sem`
- `https://stackoverflow.com/questions/123456/how-to-test`

Suspicious/high-risk URL examples:

- `http://suspicious-login.tk/verify?user=test@bank.com`
- `https://secure-update-account-verification.xyz/login`
- `http://paypal-secure-check.com.bad-site.net/auth`
- `http://free-prize-claim.win/winner?id=12345`

Email tests:

- Urgent account suspension sample.
- Lottery winner sample.
- Normal meeting invite sample.
- Password reset sample.

API test example:

```bash
curl -X POST "$API_URL/api/v1/scan-url" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"demo","url":"http://suspicious-login.tk/verify"}'
```

## 18. End-to-End Flows

### 18.1 Mock Frontend URL Scan

```text
User enters URL
  -> scanUrl()
  -> mockScanUrl()
  -> displayResults()
  -> addToHistory()
  -> localStorage
  -> optional firebaseSaveReport()
  -> optional graph node/edge Firestore writes
```

### 18.2 API URL Scan

```text
User enters URL
  -> scanUrl()
  -> POST /api/v1/scan-url
  -> scan_url.lambda_handler()
  -> analyze_url()
  -> extract_url_features()
  -> predict_url_threat()
  -> get_combined_reputation()
  -> build_scan_graph()
  -> compute_graph_suspicion()
  -> calculate_risk()
  -> Firestore threat_reports / graph collections
  -> JSON response
  -> displayResults()
  -> browser history cache
```

### 18.3 Email Scan

```text
User pastes email
  -> scanEmail()
  -> mockScanEmail() OR POST /api/v1/scan-email
  -> analyze_email()
  -> extract_email_features()
  -> predict_email_threat()
  -> optional reputation/graph scoring
  -> calculate_risk()
  -> Firestore report
  -> UI result/history update
```

### 18.4 QR Scan

```text
User uploads QR image
  -> FileReader base64 conversion
  -> scanQr()
  -> mockScanQr() OR POST /api/v1/scan-qr
  -> decode_qr()
  -> extract URL
  -> URL threat pipeline
  -> Firestore report
  -> UI result/history/graph update
```

## 19. Security and Privacy Notes

Current MVP risks:

- Firebase Web SDK can write directly from the browser.
- Public Firestore rules can allow unwanted reads/writes/deletes.
- `firebaseClearHistory()` and `firebaseClearGraphData()` can delete entire collections.
- API Gateway CORS allows all origins.
- No authentication is implemented.
- Email text is stored up to 500 characters in backend reports.
- Reputation and domain age checks are simulated.

Recommended improvements:

- Add Firebase Authentication or another auth system.
- Restrict Firestore rules by authenticated user and operation.
- Remove or protect global delete functions.
- Restrict CORS to trusted frontend domains.
- Store less sensitive email data.
- Move production writes to backend only.
- Use Secret Manager or encrypted Lambda environment variables for service account data.
- Replace simulated reputation checks with real threat intelligence APIs.
- Add structured logs and error monitoring.

## 20. Known MVP Limitations

- Mock mode scores include random components.
- ML models use synthetic data.
- Domain age and reputation are simulated.
- QR backend decoding depends on optional/native dependencies.
- Frontend and backend can both write to the same Firestore collections.
- No user authentication or per-user data isolation is currently enforced.
- SAM template does not yet fully configure Firebase credentials.
- Current backend dependency file must stay synchronized with imports.

## 21. Demo Script

Suggested demo sequence:

1. Open `index.html`.
2. Scan a safe URL such as `https://google.com`.
3. Scan a suspicious URL from `test_data.md`.
4. Explain the risk score and breakdown.
5. Paste a phishing email sample.
6. Show the History tab and filters.
7. Show Graph View and explain user/domain/IP relationships.
8. Export the raw JSON report.
9. Explain that Firestore stores `threat_reports`, `graph_nodes`, and `graph_edges`.
10. Explain AWS mode: API Gateway -> Lambda -> Firebase Admin SDK -> Firestore.

## 22. File-by-File Summary

`index.html`
: Main dashboard markup, inline design system, Firebase SDK imports, and script loading.

`enhanced.css`
: Polished UI styles for analytics, history, toasts, bulk scan, responsiveness, and footer.

`app.js`
: Frontend state, tab navigation, scan functions, mock API, result rendering, localStorage, and optional Firebase sync.

`enhanced-features.js`
: Toasts, analytics, exports, history filtering, bulk scan, threat feed, shortcuts, and result wrapping.

`graph_visualization.js`
: D3 force-directed graph renderer.

`firebase-config.js`
: Firebase Web SDK setup and browser Firestore helper functions.

`backend/utils/firebase_client.py`
: Firebase Admin SDK initialization and Firestore collection helpers.

`backend/handlers/scan_url.py`
: Lambda handler for URL scanning.

`backend/handlers/scan_email.py`
: Lambda handler for email phishing scanning.

`backend/handlers/scan_qr.py`
: Lambda handler for QR decoding and URL scanning.

`backend/threat_modules/url_analyzer.py`
: URL ML/rule analysis orchestration.

`backend/threat_modules/email_analyzer.py`
: Email phishing ML/rule analysis orchestration.

`backend/threat_modules/qr_decoder.py`
: QR image decoding and URL extraction.

`backend/threat_modules/reputation_checker.py`
: Simulated domain/IP reputation scoring.

`backend/utils/feature_extractor.py`
: URL/email feature extraction and explanation generation.

`backend/utils/ml_model.py`
: Custom logistic regression and naive Bayes models using synthetic training data.

`backend/graph_engine/graph_builder.py`
: Firestore graph node/edge creation and updates.

`backend/graph_engine/graph_metrics.py`
: Firestore graph frequency, centrality, burst, and graph suspicion metrics.

`backend/risk_engine/risk_calculator.py`
: Weighted risk score, risk level, and confidence calculation.

`infrastructure/template.yaml`
: AWS SAM template for API Gateway and Lambda functions.

`test_data.md`
: Manual test samples for URLs and email content.

## 23. Pre-Submission Checklist

- Confirm `CONFIG.MOCK_MODE` is correct.
- Confirm `CONFIG.USE_FIREBASE` is correct.
- Confirm Firebase config belongs to the intended Firebase project.
- Confirm Firestore rules are safe for the demo environment.
- Confirm backend dependencies include the packages imported by the code.
- Confirm Lambda has Firebase Admin credentials.
- Test URL, email, QR, bulk scan, graph, history, raw JSON, and export.
- Clear browser localStorage before a clean demo if needed.
- Avoid exposing public delete permissions on Firestore collections.

