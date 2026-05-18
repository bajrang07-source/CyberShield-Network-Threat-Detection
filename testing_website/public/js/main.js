/**
 * FitZone Gym - Main JavaScript
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Navbar Scroll Effect
  const navbar = document.getElementById('mainNavbar');
  if (navbar) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 50) {
        navbar.classList.add('scrolled');
      } else {
        navbar.classList.remove('scrolled');
      }
    });
    // Check on load
    if (window.scrollY > 50) navbar.classList.add('scrolled');
  }

  // 2. Animated Counter (Hero Section)
  const counters = document.querySelectorAll('.stat-number');
  if (counters.length > 0) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const target = parseInt(entry.target.getAttribute('data-target'));
          let count = 0;
          const duration = 2000; // ms
          const increment = target / (duration / 16); // 60fps

          const updateCount = () => {
            count += increment;
            if (count < target) {
              entry.target.innerText = Math.ceil(count);
              requestAnimationFrame(updateCount);
            } else {
              entry.target.innerText = target;
            }
          };
          updateCount();
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.5 });

    counters.forEach(counter => observer.observe(counter));
  }

  // 3. Password Visibility Toggle
  const toggleButtons = document.querySelectorAll('.toggle-password');
  toggleButtons.forEach(btn => {
    btn.addEventListener('click', function() {
      const input = this.previousElementSibling;
      const icon = this.querySelector('i');
      
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    });
  });

  // 4. Password Strength Indicator (Signup Page)
  const passInput = document.getElementById('signup-password');
  const strengthFill = document.getElementById('strength-fill');
  const strengthLabel = document.getElementById('strength-label');

  if (passInput && strengthFill && strengthLabel) {
    passInput.addEventListener('input', function() {
      const val = this.value;
      let strength = 0;
      
      if (val.length >= 6) strength += 25;
      if (val.length >= 10) strength += 25;
      if (/[A-Z]/.test(val)) strength += 25;
      if (/[0-9]/.test(val) || /[^A-Za-z0-9]/.test(val)) strength += 25;

      strengthFill.style.width = strength + '%';
      
      if (val.length === 0) {
        strengthFill.style.width = '0%';
        strengthFill.style.backgroundColor = 'transparent';
        strengthLabel.innerText = '';
      } else if (strength <= 25) {
        strengthFill.style.backgroundColor = '#ff4757';
        strengthLabel.innerText = 'Weak';
        strengthLabel.style.color = '#ff4757';
      } else if (strength <= 50) {
        strengthFill.style.backgroundColor = '#ffa502';
        strengthLabel.innerText = 'Fair';
        strengthLabel.style.color = '#ffa502';
      } else if (strength <= 75) {
        strengthFill.style.backgroundColor = '#2ed573';
        strengthLabel.innerText = 'Good';
        strengthLabel.style.color = '#2ed573';
      } else {
        strengthFill.style.backgroundColor = '#1e90ff';
        strengthLabel.innerText = 'Strong';
        strengthLabel.style.color = '#1e90ff';
      }
    });
  }

  // 5. Auto-dismiss Alerts
  const alerts = document.querySelectorAll('.alert-custom');
  if (alerts.length > 0) {
    setTimeout(() => {
      alerts.forEach(alert => {
        alert.style.transition = 'opacity 0.5s ease';
        alert.style.opacity = '0';
        setTimeout(() => alert.remove(), 500);
      });
    }, 5000); // 5 seconds
  }
});
