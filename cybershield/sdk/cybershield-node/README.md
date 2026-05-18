# cybershield-agent

CyberShield Universal — Node.js / Express middleware SDK.

## Installation

```bash
npm install cybershield-agent
```

## Quick Start

```js
const express = require('express')
const cybershield = require('cybershield-agent')

const app = express()
app.use(express.json())

// Add CyberShield middleware
app.use(cybershield({
  apiKey: 'cs_live_your_api_key_here',
  endpoint: 'https://your-cybershield-server.com',
  mode: 'block',          // 'block' | 'monitor'
  timeout: 3000,          // ms
}))

app.get('/', (req, res) => {
  res.json({ message: 'Protected by CyberShield!' })
})

app.listen(3000)
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | string | **required** | Your site API key (starts with `cs_live_`) |
| `endpoint` | string | `http://localhost:5000` | CyberShield server URL |
| `mode` | string | `'block'` | `'block'` — reject threats; `'monitor'` — pass through but log |
| `timeout` | number | `3000` | HTTP timeout in milliseconds |
| `maxQueueSize` | number | `100` | Offline queue size (requests buffered when server unreachable) |
| `onBlock` | function | `null` | Custom handler `(req, res, result) => {}` when request is blocked |

## Behavior

- **Blocked requests**: Returns `403 JSON` with `attack_type` and `risk_score`.
- **Offline/unreachable**: Requests are queued (up to `maxQueueSize`) and retried. Traffic passes through in offline mode.
- **Attach result**: `req.cybershield` is populated with the analysis result for downstream middleware.

## Custom Block Handler

```js
app.use(cybershield({
  apiKey: 'cs_live_...',
  mode: 'block',
  onBlock: (req, res, result) => {
    res.status(403).render('blocked', { attackType: result.attack_type })
  }
}))
```

## Result Object

```json
{
  "risk_score": 92.5,
  "attack_type": "SQL_INJECTION",
  "severity": "CRITICAL",
  "action": "block",
  "matched_pattern": "SQLI: OR 1=1",
  "ml_score": 0.9134,
  "event_id": "uuid..."
}
```
