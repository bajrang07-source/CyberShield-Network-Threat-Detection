/**
 * isLoggedIn middleware
 * Protects routes that require authentication.
 * Redirects to /auth/login if the user is not in session.
 */
function isLoggedIn(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  req.session.returnTo = req.originalUrl;
  res.redirect('/auth/login');
}

module.exports = { isLoggedIn };
