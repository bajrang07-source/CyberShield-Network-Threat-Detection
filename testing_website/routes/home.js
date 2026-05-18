const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('pages/home', {
    title: 'FitZone Gym - Transform Your Body, Transform Your Life',
  });
});

module.exports = router;
