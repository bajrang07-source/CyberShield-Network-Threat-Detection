const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const usersFile = path.join(__dirname, '../data/users.json');

function readUsers() {
  try {
    const data = fs.readFileSync(usersFile, 'utf-8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function writeUsers(data) {
  fs.writeFileSync(usersFile, JSON.stringify(data, null, 2));
}

// ─── GET /auth/login ─────────────────────────────────────────────────────────
router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('pages/login', {
    title: 'Login - FitZone Gym',
    error: null,
  });
});

// ─── POST /auth/login ─────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('pages/login', {
      title: 'Login - FitZone Gym',
      error: 'Email and password are required.',
    });
  }

  const users = readUsers();
  const user = users.find((u) => u.email.toLowerCase() === email.toLowerCase().trim());

  if (!user) {
    return res.render('pages/login', {
      title: 'Login - FitZone Gym',
      error: 'Invalid email or password.',
    });
  }

  try {
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render('pages/login', {
        title: 'Login - FitZone Gym',
        error: 'Invalid email or password.',
      });
    }

    // Store safe user info in session
    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      membership: user.membership,
    };

    const returnTo = req.session.returnTo || '/dashboard';
    delete req.session.returnTo;
    res.redirect(returnTo);
  } catch (err) {
    console.error(err);
    res.render('pages/login', {
      title: 'Login - FitZone Gym',
      error: 'An error occurred. Please try again.',
    });
  }
});

// ─── GET /auth/signup ─────────────────────────────────────────────────────────
router.get('/signup', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('pages/signup', {
    title: 'Sign Up - FitZone Gym',
    error: null,
  });
});

// ─── POST /auth/signup ────────────────────────────────────────────────────────
router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  // Validate inputs
  if (!name || !email || !password) {
    return res.render('pages/signup', {
      title: 'Sign Up - FitZone Gym',
      error: 'All fields are required.',
    });
  }

  if (name.trim().length < 2) {
    return res.render('pages/signup', {
      title: 'Sign Up - FitZone Gym',
      error: 'Name must be at least 2 characters.',
    });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.render('pages/signup', {
      title: 'Sign Up - FitZone Gym',
      error: 'Please enter a valid email address.',
    });
  }

  if (password.length < 6) {
    return res.render('pages/signup', {
      title: 'Sign Up - FitZone Gym',
      error: 'Password must be at least 6 characters.',
    });
  }

  const users = readUsers();
  const existingUser = users.find(
    (u) => u.email.toLowerCase() === email.toLowerCase().trim()
  );

  if (existingUser) {
    return res.render('pages/signup', {
      title: 'Sign Up - FitZone Gym',
      error: 'An account with this email already exists.',
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: `user_${Date.now()}`,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      password: hashedPassword,
      membership: 'Basic',
      joinedAt: new Date().toISOString(),
    };

    users.push(newUser);
    writeUsers(users);

    // Auto-login after signup
    req.session.user = {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      membership: newUser.membership,
    };

    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('pages/signup', {
      title: 'Sign Up - FitZone Gym',
      error: 'An error occurred. Please try again.',
    });
  }
});

// ─── GET /auth/logout ─────────────────────────────────────────────────────────
router.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error(err);
    res.redirect('/');
  });
});

module.exports = router;
