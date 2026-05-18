const express = require('express');
const router = express.Router();

const trainers = [
  {
    id: 1,
    name: 'John Carter',
    specialization: 'Strength Coach',
    experience: '8 Years',
    bio: 'Expert in powerlifting, muscle building, and strength conditioning. Certified NSCA coach.',
    image: 'https://images.unsplash.com/photo-1567013127542-490d757e51fc?w=400&h=500&fit=crop&q=80',
    rating: 4.9,
  },
  {
    id: 2,
    name: 'Alex Rivera',
    specialization: 'Cardio Trainer',
    experience: '6 Years',
    bio: 'Specializes in HIIT, endurance training, and fat-loss programs. Marathon runner and cycling enthusiast.',
    image: 'https://images.unsplash.com/photo-1571019614242-c5c5dee9f50b?w=400&h=500&fit=crop&q=80',
    rating: 4.8,
  },
  {
    id: 3,
    name: 'Sarah Mitchell',
    specialization: 'Yoga & Flexibility',
    experience: '10 Years',
    bio: 'Certified yoga instructor with expertise in Hatha, Vinyasa, and restorative yoga. Mindfulness advocate.',
    image: 'https://images.unsplash.com/photo-1518611012118-696072aa579a?w=400&h=500&fit=crop&q=80',
    rating: 5.0,
  },
];

router.get('/', (req, res) => {
  res.render('pages/trainers', {
    title: 'Our Trainers - FitZone Gym',
    trainers,
  });
});

module.exports = router;
