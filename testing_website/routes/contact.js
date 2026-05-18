const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const contactFile = path.join(__dirname, '../data/contact.json');

function readContacts() {
  try {
    const data = fs.readFileSync(contactFile, 'utf-8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function writeContacts(data) {
  fs.writeFileSync(contactFile, JSON.stringify(data, null, 2));
}

router.get('/', (req, res) => {
  res.render('pages/contact', {
    title: 'Contact Us - FitZone Gym',
    success: null,
    error: null,
  });
});

router.post('/', (req, res) => {
  const { name, email, message } = req.body;

  // Basic validation
  if (!name || !email || !message) {
    return res.render('pages/contact', {
      title: 'Contact Us - FitZone Gym',
      success: null,
      error: 'All fields are required.',
    });
  }

  if (name.trim().length < 2) {
    return res.render('pages/contact', {
      title: 'Contact Us - FitZone Gym',
      success: null,
      error: 'Name must be at least 2 characters.',
    });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.render('pages/contact', {
      title: 'Contact Us - FitZone Gym',
      success: null,
      error: 'Please enter a valid email address.',
    });
  }

  if (message.trim().length < 10) {
    return res.render('pages/contact', {
      title: 'Contact Us - FitZone Gym',
      success: null,
      error: 'Message must be at least 10 characters.',
    });
  }

  const contacts = readContacts();
  const newContact = {
    id: `contact_${Date.now()}`,
    name: name.trim(),
    email: email.trim().toLowerCase(),
    message: message.trim(),
    submittedAt: new Date().toISOString(),
  };

  contacts.push(newContact);
  writeContacts(contacts);

  res.render('pages/contact', {
    title: 'Contact Us - FitZone Gym',
    success: 'Thank you! Your message has been received. We will get back to you soon.',
    error: null,
  });
});

module.exports = router;
