# 🏋️ FitZone Gym Website

A complete gym website built with **Node.js + Express.js** for demo and cybersecurity testing purposes.

## 🚀 Quick Start

```bash
npm install
npm start
```

Visit: **http://localhost:3000**

## 🔐 Demo Login Credentials

| Email | Password | Membership |
|-------|----------|------------|
| alice@example.com | password123 | Pro |
| bob@example.com | password123 | Basic |
| carol@example.com | password123 | Premium |
| dan@example.com | password123 | Basic |
| eve@example.com | password123 | Pro |

## 📄 Pages

| Route | Page |
|-------|------|
| `/` | Home |
| `/about` | About Us |
| `/membership` | Membership Plans |
| `/trainers` | Trainers |
| `/contact` | Contact Form |
| `/auth/login` | Login |
| `/auth/signup` | Sign Up |
| `/dashboard` | User Dashboard (protected) |

## 🛠️ Tech Stack

- **Backend:** Node.js, Express.js, express-session, bcrypt, helmet
- **Frontend:** EJS, Bootstrap 5, Vanilla CSS, Vanilla JS
- **Storage:** JSON files (no database)

## 📁 Project Structure

```
testing_website/
├── routes/          # Express route handlers
├── middleware/      # Auth middleware
├── data/            # JSON data storage
│   ├── users.json
│   ├── workouts.json
│   └── contact.json
├── public/          # Static assets
│   ├── css/style.css
│   └── js/main.js
├── views/           # EJS templates
│   ├── pages/
│   └── partials/
├── server.js
├── .env
└── package.json
```

## ⚠️ Disclaimer

This website is built for **demo and cybersecurity testing purposes only**. No real payment processing or production-grade security is implemented.
