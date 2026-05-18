/**
 * CyberShield Universal — Node.js / Express Middleware SDK
 *
 * Usage:
 *   const cybershield = require('cybershield-agent');
 *   app.use(cybershield({ apiKey: 'cs_live_...', mode: 'monitor' }));
 *
 * Options:
 *   apiKey        (required) — your site API key
 *   endpoint      CyberShield ingest URL (default: http://localhost:5000)
 *   mode          'monitor' | 'block' (default: 'block')
 *   timeout       HTTP timeout ms (default: 3000)
 *   maxQueueSize  offline queue size (default: 100)
 *   onBlock       optional callback(req, res, result) for custom block handling
 */

'use strict';

const axios = require('axios');

const DEFAULT_ENDPOINT = 'http://localhost:5000';
const DEFAULT_TIMEOUT = 3000;
const DEFAULT_QUEUE_SIZE = 100;

// Offline queue for when CyberShield is unreachable
const _queue = [];
let _draining = false;

/**
 * Send telemetry to CyberShield with retry logic.
 * Returns the parsed result or null on failure.
 */
async function _send(payload, apiKey, endpoint, timeout, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await axios.post(`${endpoint}/api/ingest`, payload, {
        headers: {
          'Content-Type': 'application/json',
          'X-CS-API-Key': apiKey,
        },
        timeout,
      });
      return response.data;
    } catch (err) {
      if (attempt === retries) {
        // Queue for later if completely offline
        return null;
      }
      await _sleep(200 * Math.pow(2, attempt));
    }
  }
  return null;
}

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Drain the offline queue when connectivity is restored.
 */
async function _drainQueue(apiKey, endpoint, timeout) {
  if (_draining || _queue.length === 0) return;
  _draining = true;
  while (_queue.length > 0) {
    const item = _queue.shift();
    await _send(item, apiKey, endpoint, timeout, 1);
    await _sleep(100);
  }
  _draining = false;
}

/**
 * Extract the real client IP.
 */
function _getIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || req.ip || '0.0.0.0';
}

/**
 * Build the telemetry payload from an Express request.
 */
function _buildPayload(req) {
  return {
    ip: _getIP(req),
    user_agent: req.headers['user-agent'] || '',
    path: req.originalUrl || req.url || '/',
    method: req.method || 'GET',
    payload: req.body || {},
    headers: _safeHeaders(req.headers),
    session_id: req.session?.id || req.cookies?.session || '',
    timestamp: new Date().toISOString(),
  };
}

/**
 * Strip sensitive headers before forwarding.
 */
function _safeHeaders(headers) {
  const SKIP = new Set(['authorization', 'cookie', 'x-cs-api-key']);
  const safe = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (!SKIP.has(k.toLowerCase())) safe[k] = v;
  }
  return safe;
}

/**
 * Main middleware factory.
 */
function cybershield(options = {}) {
  const {
    apiKey,
    endpoint = DEFAULT_ENDPOINT,
    mode = 'block',
    timeout = DEFAULT_TIMEOUT,
    maxQueueSize = DEFAULT_QUEUE_SIZE,
    onBlock,
  } = options;

  if (!apiKey) throw new Error('[CyberShield] apiKey is required');

  return async function cybershieldMiddleware(req, res, next) {
    const payload = _buildPayload(req);

    // Fire-and-forget drain attempt
    _drainQueue(apiKey, endpoint, timeout).catch(() => {});

    let result = null;
    try {
      result = await _send(payload, apiKey, endpoint, timeout);
    } catch {
      // Offline — queue and pass through
    }

    if (!result) {
      // Queue for retry
      if (_queue.length < maxQueueSize) _queue.push(payload);
      return next();
    }

    // Block if instructed (and mode allows it)
    if (result.action === 'block' && mode === 'block') {
      if (typeof onBlock === 'function') {
        return onBlock(req, res, result);
      }
      res.status(403).json({
        error: 'Access denied by CyberShield',
        attack_type: result.attack_type,
        risk_score: result.risk_score,
      });
      return;
    }

    // Attach result for downstream logging
    req.cybershield = result;
    return next();
  };
}

module.exports = cybershield;
module.exports.cybershield = cybershield;
