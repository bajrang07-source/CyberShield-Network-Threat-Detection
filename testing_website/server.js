require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const cybershield = require('./cybershield');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Helmet Security ─────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          'cdn.jsdelivr.net',
          'cdnjs.cloudflare.com',
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'cdn.jsdelivr.net',
          'cdnjs.cloudflare.com',
          'fonts.googleapis.com',
        ],
        fontSrc: ["'self'", 'fonts.googleapis.com', 'fonts.gstatic.com', 'cdnjs.cloudflare.com'],
        imgSrc: ["'self'", 'data:', 'via.placeholder.com', 'images.unsplash.com', 'https://images.unsplash.com'],
        connectSrc: ["'self'"],
      },
    },
  })
);

// ─── Body Parsers (MUST be before CyberShield so POST payloads are visible) ──
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ─── CyberShield Protection ──────────────────────────────────────────────────
if (process.env.CYBERSHIELD_API_KEY) {
  app.use(cybershield({
    apiKey:   process.env.CYBERSHIELD_API_KEY,
    endpoint: process.env.CYBERSHIELD_ENDPOINT || 'http://localhost:5000',
    mode:     process.env.CYBERSHIELD_MODE     || 'block',
    // Custom block page — shown in browser instead of raw JSON
    onBlock: (req, res, result) => {
      res.status(403).send(`
        <!DOCTYPE html>
        <html>
        <head><title>Access Denied - CyberShield</title>
        <style>
          body { font-family: Arial, sans-serif; background: #0a0a1a; color: #fff;
                 display: flex; align-items: center; justify-content: center;
                 min-height: 100vh; margin: 0; }
          .box { background: #1a1a2e; border: 2px solid #e74c3c; border-radius: 12px;
                 padding: 40px; max-width: 500px; text-align: center; }
          h1 { color: #e74c3c; font-size: 28px; margin-bottom: 10px; }
          .badge { background: #e74c3c; color: #fff; padding: 4px 12px;
                   border-radius: 20px; font-size: 13px; display: inline-block; margin: 8px 0; }
          .score { font-size: 48px; font-weight: bold; color: #e74c3c; margin: 16px 0; }
          p { color: #aaa; line-height: 1.6; }
          a { color: #3498db; text-decoration: none; }
          .shield { font-size: 64px; margin-bottom: 16px; }
        </style></head>
        <body>
          <div class="box">
            <div class="shield">🛡️</div>
            <h1>Access Blocked</h1>
            <span class="badge">${result.attack_type || 'THREAT DETECTED'}</span>
            <div class="score">${Math.round(result.risk_score)}<small style="font-size:18px">/100</small></div>
            <p>CyberShield detected a <strong>${result.severity || 'HIGH'}</strong> severity attack
               from your IP address. This request has been blocked and logged.</p>
            <p><a href="/">← Return to homepage</a></p>
            <p style="font-size:11px;color:#555;margin-top:20px">Protected by CyberShield Universal</p>
          </div>
        </body></html>
      `);
    },
  }));
  console.log('Shield CyberShield protection ACTIVE (mode:', process.env.CYBERSHIELD_MODE || 'block', ')');
} else {
  console.warn('WARNING: CYBERSHIELD_API_KEY not set - protection disabled. Add it to .env');
}

// ─── Session ──────────────────────────────────────────────────────────────────
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'fitzone_secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 2, // 2 hours
      secure: process.env.NODE_ENV === 'production',
    },
  })
);

// ─── View Engine ──────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Static Files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Local vars middleware (pass user to all views) ──────────────────────────
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// ─── Routes ───────────────────────────────────────────────────────────────────
const homeRoute      = require('./routes/home');
const aboutRoute     = require('./routes/about');
const membershipRoute = require('./routes/membership');
const trainersRoute  = require('./routes/trainers');
const contactRoute   = require('./routes/contact');
const authRoute      = require('./routes/auth');
const dashboardRoute = require('./routes/dashboard');

app.use('/', homeRoute);
app.use('/about', aboutRoute);
app.use('/membership', membershipRoute);
app.use('/trainers', trainersRoute);
app.use('/contact', contactRoute);
app.use('/auth', authRoute);
app.use('/dashboard', dashboardRoute);

// ─── 404 Handler ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).render('pages/404', { title: '404 - Page Not Found' });
});

// ─── Error Handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('pages/404', { title: '500 - Server Error' });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🏋️  FitZone Gym server running at http://localhost:${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}\n`);
});
