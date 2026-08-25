'use strict';

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');

const router = express.Router();
const ROOT = path.resolve(__dirname, '..', '..', 'uploads');

/** Serve a file from uploads/. */
router.get('/attachments', (req, res) => {
  const name = String(req.query.name || '');
  const target = path.resolve(ROOT, name);

  if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
    return res.status(404).send('Not found');
  }
  res.type('text/plain; charset=utf-8').send(fs.readFileSync(target));
});

module.exports = router;
