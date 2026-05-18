const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('pages/about', {
    title: 'About Us - FitZone Gym',
  });
});

module.exports = router;
