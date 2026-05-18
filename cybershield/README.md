# CyberShield — Real-Time Web Attack Detection System

> A production-ready ML-powered intrusion detection system with live WebSocket dashboard, rule-based + ensemble ML detection, and automatic IP blocking.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser                                  │
│              React Frontend (Vite + Tailwind)                    │
│         Dashboard │ Attacks │ Blocked IPs │ Settings             │
└───────────────┬─────────────────────────┬───────────────────────┘
                │ HTTP /api/*             │ WebSocket /socket.io
                ▼                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Flask Backend (Gunicorn + Eventlet)           │
│                                                                  │
│  before_request interceptor                                      │
│       │                                                          │
│       ├─► Feature Extractor  (11 features + Redis rate counters) │
│       ├─► Rule Engine        (Regex: SQLi/XSS/CMDi/Traversal)   │
│       ├─► ML Engine          (IsolationForest + LR ensemble)     │
│       └─► Response Engine    (Block / Rate-limit / Alert / Log)  │
│                                                                  │
│  REST API Blueprint   │  SocketIO Events                         │
│  /api/stats           │  new_attack                              │
│  /api/attacks         │  ip_blocked                              │
│  /api/blocked-ips     │  stats_update                            │
│  /api/settings        │  request_tick                            │
└───────────┬───────────────────────────┬─────────────────────────┘
            │                           │
            ▼                           ▼
     ┌─────────────┐            ┌─────────────────┐
     │   SQLite    │            │      Redis       │
     │  (via SA)   │            │  (blocks/rates)  │
     └─────────────┘            └─────────────────┘
```

## Features

- 🛡️ **Rule Engine** — Regex detection for SQLi, XSS, Path Traversal, Command Injection, Brute Force, Honeypots
- 🤖 **ML Ensemble** — IsolationForest (anomaly) + LogisticRegression (classification), 0.6/0.4 weighted
- 📊 **Live Dashboard** — Real-time SocketIO traffic chart, threat feed, stat cards
- 🚫 **Auto-blocking** — Redis-backed IP blocking with configurable TTL
- 🌍 **Geo Enrichment** — Async ip-api.com lookup for blocked IPs
- 🔔 **Webhooks** — Slack/custom webhook dispatch for CRITICAL alerts
- 📈 **Recharts Visualizations** — Area chart, donut chart, timeline

---

## Quick Start

### Option A: Docker (Recommended)

```bash
git clone <repo>
cd cybershield
cp .env.example .env
docker-compose up --build
```

Open: http://localhost:3000 | Login: `admin / cybershield123`

### Option B: Manual

```bash
# Backend
cd backend
pip install -r requirements.txt
python ml/generate_dataset.py
python ml/train_model.py
flask run --port 5000

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

---

## Demo Test Scripts

```bash
# 1. Health check
curl http://localhost:5000/api/health

# 2. Login and get JWT
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"cybershield123"}' | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 3. Simulate SQL Injection
curl -X POST http://localhost:5000/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": "'\'' OR 1=1 UNION SELECT * FROM users--"}'

# 4. Trigger XSS detection
curl -X POST http://localhost:5000/api/comment \
  -H "Content-Type: application/json" \
  -d '{"body": "<script>alert(document.cookie)</script>"}'

# 5. Hit honeypot path
curl http://localhost:5000/.env
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `cybershield-secret-key-change-in-prod` | Flask secret key |
| `JWT_SECRET` | `cybershield-jwt-secret-change-in-prod` | JWT signing key |
| `DATABASE_URL` | `sqlite:///cybershield.db` | SQLAlchemy database URL |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `ADMIN_USER` | `admin` | Admin dashboard username |
| `ADMIN_PASS` | `cybershield123` | Admin dashboard password |
| `BLOCK_DURATION_SECONDS` | `86400` | Default IP block duration (1 day) |
| `CRITICAL_THRESHOLD` | `80` | Risk score to trigger auto-block |
| `HIGH_THRESHOLD` | `60` | Risk score for rate-limiting |
| `MEDIUM_THRESHOLD` | `40` | Risk score for alerting |
| `ML_WEIGHT` | `0.6` | ML component weight in ensemble |
| `BRUTE_FORCE_RATE_LIMIT` | `10` | Req/min threshold for brute force |
| `WEBHOOK_URL` | _(empty)_ | Slack/webhook URL for CRITICAL alerts |

---

## API Reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | No | Get JWT token |
| `GET` | `/api/health` | No | System health + model status |
| `GET` | `/api/stats` | JWT | 24h aggregate statistics |
| `GET` | `/api/attacks` | JWT | Paginated attack log (filterable) |
| `GET` | `/api/attacks/<id>` | JWT | Full attack detail + IP timeline |
| `GET` | `/api/blocked-ips` | JWT | Active blocked IPs |
| `POST` | `/api/blocked-ips/block` | JWT | Manual IP block |
| `POST` | `/api/blocked-ips/unblock` | JWT | Unblock IP |
| `GET` | `/api/traffic-timeline` | JWT | Per-minute traffic history |
| `GET` | `/api/threat-breakdown` | JWT | Attack type distribution |
| `GET` | `/api/settings` | JWT | All settings |
| `PUT` | `/api/settings` | JWT | Update settings |
| `POST` | `/api/simulate-attack` | JWT | Run detection without logging |
| `GET` | `/api/whitelist` | JWT | Whitelisted IPs |
| `POST` | `/api/whitelist` | JWT | Add IP to whitelist |
| `DELETE` | `/api/whitelist/<ip>` | JWT | Remove IP from whitelist |

---

## Running Tests

```bash
cd backend
pytest tests/ -v

# Run specific suite
pytest tests/test_rule_engine.py -v
pytest tests/test_ml_engine.py -v
pytest tests/test_attack_simulations.py -v
```

---

## ML Model Details

- **Dataset**: 10,000 labeled samples (7k normal, 1.5k SQLi, 1k XSS, 0.5k brute force)
- **Features**: 11 features (payload length, special chars, SQL keywords, XSS patterns, path traversal, rate limits × 2, bad UA, entropy, query params, method)
- **IsolationForest**: `n_estimators=200, contamination=0.15` — unsupervised anomaly detection
- **LogisticRegression**: `max_iter=1000, class_weight=balanced` — supervised classification
- **Ensemble**: `0.6 × IF_score + 0.4 × LR_score`
- **Retrain**: `python ml/generate_dataset.py && python ml/train_model.py`

---

## Project Structure

```
cybershield/
├── backend/
│   ├── app.py                     # Flask app + SocketIO
│   ├── config.py                  # Environment config
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── ml/
│   │   ├── generate_dataset.py    # 10k row dataset generator
│   │   ├── train_model.py         # IF + LR ensemble trainer
│   │   └── model.pkl              # (generated)
│   ├── models/
│   │   ├── db.py                  # SQLAlchemy models
│   │   └── schemas.py             # Marshmallow schemas
│   ├── detection/
│   │   ├── feature_extractor.py   # 11-feature extractor
│   │   ├── rule_engine.py         # Regex rule engine
│   │   └── ml_engine.py           # ML singleton
│   ├── middleware/
│   │   ├── interceptor.py         # before_request hook
│   │   └── response_engine.py     # CRITICAL/HIGH/MEDIUM/LOW handlers
│   ├── api/
│   │   ├── dashboard.py           # REST API blueprint
│   │   └── events.py              # SocketIO emitters
│   └── tests/
│       ├── test_rule_engine.py
│       ├── test_ml_engine.py
│       └── test_attack_simulations.py
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── pages/                 # Dashboard, Attacks, BlockedIPs, Settings, Login
│   │   ├── components/            # Layout, Dashboard, Attacks components
│   │   ├── hooks/                 # useStats, useSocketFeed
│   │   ├── store/                 # Zustand store
│   │   └── lib/                   # api.js, socket.js
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
├── .env.example
└── README.md
```
