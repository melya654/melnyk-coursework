'use strict';
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('node:crypto');
const path = require('node:path');

const V = require('./validators');
const S = require('./security');
const { open, makeRepo, verifyPassword, DUMMY_HASH } = require('./db');

const FORGOT_LIMIT = 3; // максимум запитів відновлення на одну адресу
const FORGOT_WINDOW_MS = 60 * 60 * 1000; // за годину

function createApp(options = {}) {
  const db = open(options.dbFile);
  const repo = makeRepo(db);
  const app = express();
  const isProd = process.env.NODE_ENV === 'production';

  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // Заголовки безпеки: CSP забороняє виконання сторонніх і inline-скриптів (друга лінія захисту від XSS)
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", 'data:'],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          objectSrc: ["'none'"],
        },
      },
    })
  );

  // Обмеження розміру тіла запиту — захист від надмірних навантажень
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: false, limit: '10kb' }));
  app.use(cookieParser());

  // Сесійний ідентифікатор у HttpOnly-cookie; до нього прив'язано токен форми
  app.use((req, res, next) => {
    let sid = req.cookies.sid;
    if (typeof sid !== 'string' || !/^[a-f0-9]{32}$/.test(sid)) {
      sid = crypto.randomBytes(16).toString('hex');
      res.cookie('sid', sid, { httpOnly: true, sameSite: 'strict', secure: isProd });
    }
    req.sid = sid;
    next();
  });

  // Обмеження частоти: не більше N відправлень з однієї IP за вікно часу
  const limiter = rateLimit({
    windowMs: options.rateWindowMs || 60 * 1000,
    limit: options.rateLimit || 5,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      repo.logSpam(req.path, 'rate-limit', req.ip);
      res.status(429).json({ ok: false, errors: { _form: 'Забагато спроб. Спробуйте за хвилину.' } });
    },
  });

  app.use(express.static(path.join(__dirname, '..', 'public')));

  // Видача токена форми (CSRF + час заповнення)
  app.get('/api/form-token', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ token: S.issueFormToken(req.sid) });
  });

  // Спільна перевірка анти-спам рівня: honeypot, токен, час. Повертає true, якщо запит заблоковано.
  function guard(req, res, form) {
    if (S.isHoneypotTripped(req.body || {})) {
      repo.logSpam(form, 'honeypot', req.ip);
      // Бот отримує «успіх», щоб не підлаштовуватись; дані не зберігаються
      res.json({ ok: true });
      return true;
    }
    const t = S.checkFormToken((req.body || {}).formToken, req.sid);
    if (!t.ok) {
      repo.logSpam(form, t.reason, req.ip);
      const msg =
        t.reason === 'too-fast'
          ? 'Форму надіслано занадто швидко. Спробуйте ще раз.'
          : 'Сесія форми недійсна або застаріла. Оновіть сторінку.';
      res.status(t.reason === 'too-fast' ? 429 : 403).json({ ok: false, errors: { _form: msg } });
      return true;
    }
    return false;
  }

  function fail(res, errors) {
    const clean = {};
    for (const [k, v] of Object.entries(errors)) if (v) clean[k] = v;
    if (Object.keys(clean).length === 0) return false;
    res.status(422).json({ ok: false, errors: clean });
    return true;
  }

  // --- Форма 1: реєстрація ---
  app.post('/api/signup', limiter, (req, res) => {
    if (guard(req, res, 'signup')) return;
    const b = req.body || {};
    const data = {
      firstName: V.normalize(b.firstName),
      lastName: V.normalize(b.lastName),
      email: V.normalize(b.email).toLowerCase(),
      phone: V.normalizePhone(b.phone),
      country: typeof b.country === 'string' ? b.country : '',
      password: typeof b.password === 'string' ? b.password : '',
    };
    const confirm = typeof b.passwordConfirm === 'string' ? b.passwordConfirm : '';
    if (
      fail(res, {
        firstName: V.validateName(data.firstName, 'Імʼя'),
        lastName: V.validateName(data.lastName, 'Прізвище'),
        email: V.validateEmail(data.email),
        phone: V.validatePhone(data.phone),
        country: V.validateCountry(data.country),
        password: V.validatePassword(data.password),
        passwordConfirm: data.password !== confirm ? 'Паролі не збігаються' : null,
      })
    )
      return;
    if (repo.findByEmail(data.email)) {
      return res.status(409).json({ ok: false, errors: { _form: 'Не вдалося створити акаунт із цими даними' } });
    }
    repo.addUser(data);
    res.json({ ok: true });
  });

  // --- Форма 2: вхід (демо без сесій: перевіряється лише коректність даних і облікових даних) ---
  app.post('/api/login', limiter, (req, res) => {
    if (guard(req, res, 'login')) return;
    const b = req.body || {};
    const email = V.normalize(b.email).toLowerCase();
    const password = typeof b.password === 'string' ? b.password : '';
    if (fail(res, { email: V.validateEmail(email), password: V.validateLoginPassword(password) })) return;
    const user = repo.findByEmail(email);
    // Перевірка пароля виконується завжди, навіть якщо користувача немає (однаковий час відповіді)
    const ok = verifyPassword(password, user ? user.password_hash : DUMMY_HASH) && !!user;
    if (!ok) {
      // Однакове повідомлення для «немає акаунта» і «невірний пароль»
      return res.status(401).json({ ok: false, errors: { _form: 'Невірний email або пароль' } });
    }
    res.json({ ok: true, name: user.first_name });
  });

  // --- Форма 3: відновлення пароля ---
  app.post('/api/forgot', limiter, (req, res) => {
    if (guard(req, res, 'forgot')) return;
    const email = V.normalize((req.body || {}).email).toLowerCase();
    if (fail(res, { email: V.validateEmail(email) })) return;
    // Ліміт запитів на одну адресу: захист від «бомбардування» чужої пошти листами.
    // Відповідь завжди однакова, щоб не розкривати, чи існує акаунт.
    if (repo.forgotCount(email, Date.now() - FORGOT_WINDOW_MS) >= FORGOT_LIMIT) {
      repo.logSpam('forgot', 'email-throttle', req.ip);
    } else {
      repo.addForgot(email);
      // У реальному проєкті тут надсилався б лист; у демо лист не відправляється.
    }
    res.json({ ok: true });
  });

  // Службова статистика для демонстрації (лише кількості, без персональних даних)
  app.get('/api/stats', (req, res) => res.json(repo.stats()));

  // Некоректний JSON та інші помилки — без витоку стеку
  app.use((err, req, res, next) => {
    const status = err.status || 500;
    res.status(status).json({ ok: false, errors: { _form: status === 413 ? 'Запит занадто великий' : 'Некоректний запит' } });
  });

  app.repo = repo;
  return app;
}

if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => console.log(`http://localhost:${port}`));
}

module.exports = { createApp };
