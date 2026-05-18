const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('pages/membership', {
    title: 'Membership Plans - FitZone Gym',
  });
});

module.exports = router;
