'use strict';

const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/login', (req, res) => {
  res.render('login', { error: null, query: '' });
});

router.post('/login', (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  const user = db.findUser(username);

  // verifyPassword is constant-time; the user lookup failing is handled the same
  // way as a bad password so the response does not leak which one it was.
  if (user && db.verifyPassword(password, user.password_hash)) {
    return req.session.regenerate((err) => {
      if (err) return res.status(500).send('Session error');
      req.session.userId = user.id;
      req.session.username = user.username;
      res.redirect('/');
    });
  }
  res.status(401).render('login', {
    error: 'Invalid username or password.',
    query: '',
  });
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

module.exports = router;
