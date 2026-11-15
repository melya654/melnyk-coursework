'use strict';
const { createApp } = require('./src/server');

module.exports = createApp({ dbFile: process.env.VERCEL ? '/tmp/app.db' : undefined });
