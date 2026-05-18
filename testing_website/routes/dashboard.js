const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { isLoggedIn } = require('../middleware/auth');

const workoutsFile = path.join(__dirname, '../data/workouts.json');

function readWorkouts() {
  try {
    const data = fs.readFileSync(workoutsFile, 'utf-8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function writeWorkouts(data) {
  fs.writeFileSync(workoutsFile, JSON.stringify(data, null, 2));
}

// ─── GET /dashboard ────────────────────────────────────────────────────────────
router.get('/', isLoggedIn, (req, res) => {
  const allWorkouts = readWorkouts();
  const userWorkouts = allWorkouts.filter((w) => w.userId === req.session.user.id);

  res.render('pages/dashboard', {
    title: 'Dashboard - FitZone Gym',
    workouts: userWorkouts,
    success: req.query.success || null,
    error: req.query.error || null,
  });
});

// ─── POST /dashboard/workout/add ───────────────────────────────────────────────
router.post('/workout/add', isLoggedIn, (req, res) => {
  const { name, sets, reps, duration } = req.body;

  if (!name || name.trim().length < 2) {
    return res.redirect('/dashboard?error=Workout+name+must+be+at+least+2+characters.');
  }

  const allWorkouts = readWorkouts();
  const newWorkout = {
    id: `workout_${Date.now()}`,
    userId: req.session.user.id,
    name: name.trim(),
    sets: parseInt(sets) || 1,
    reps: parseInt(reps) || 1,
    duration: (duration || '30 min').trim(),
    date: new Date().toISOString(),
  };

  allWorkouts.push(newWorkout);
  writeWorkouts(allWorkouts);

  res.redirect('/dashboard?success=Workout+added+successfully!');
});

// ─── POST /dashboard/workout/delete/:id ────────────────────────────────────────
router.post('/workout/delete/:id', isLoggedIn, (req, res) => {
  const workoutId = req.params.id;
  let allWorkouts = readWorkouts();

  const workout = allWorkouts.find((w) => w.id === workoutId);
  if (!workout || workout.userId !== req.session.user.id) {
    return res.redirect('/dashboard?error=Workout+not+found+or+unauthorized.');
  }

  allWorkouts = allWorkouts.filter((w) => w.id !== workoutId);
  writeWorkouts(allWorkouts);

  res.redirect('/dashboard?success=Workout+deleted+successfully!');
});

module.exports = router;
