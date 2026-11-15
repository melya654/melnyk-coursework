'use strict';
// Точка входу для Vercel (serverless). Локально сервер запускається через src/server.js.
// На Vercel файлова система доступна для запису лише в /tmp, тож база тут тимчасова (демо).
const { createApp } = require('../src/server');

module.exports = createApp({ dbFile: process.env.VERCEL ? '/tmp/app.db' : undefined });
