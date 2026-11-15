'use strict';
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

function open(file) {
  const target = file || path.join(__dirname, '..', 'data', 'app.db');
  if (target !== ':memory:') fs.mkdirSync(path.dirname(target), { recursive: true });
  const db = new DatabaseSync(target);
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_name TEXT NOT NULL, last_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE, phone TEXT NOT NULL, country TEXT NOT NULL,
      password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS forgot_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS spam_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      form TEXT NOT NULL, reason TEXT NOT NULL, ip TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
  return db;
}

// Хешування пароля: scrypt зі випадковою сіллю (вбудований у Node, без залежностей)
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [alg, saltHex, hashHex] = stored.split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

// Фіктивний хеш: при вході з неіснуючим email перевірка все одно виконується,
// щоб час відповіді не видавав, чи існує такий акаунт.
const DUMMY_HASH = hashPassword('dummy-password-for-timing');

// Усі запити — параметризовані (?), конкатенації рядків немає (захист від SQL-ін'єкцій)
function makeRepo(db) {
  const insertUser = db.prepare(
    'INSERT INTO users (first_name, last_name, email, phone, country, password_hash) VALUES (?, ?, ?, ?, ?, ?)'
  );
  const findByEmail = db.prepare('SELECT id, first_name, password_hash FROM users WHERE email = ?');
  const insertForgot = db.prepare('INSERT INTO forgot_requests (email, created_at) VALUES (?, ?)');
  const countForgot = db.prepare('SELECT COUNT(*) AS c FROM forgot_requests WHERE email = ? AND created_at > ?');
  const insertSpam = db.prepare('INSERT INTO spam_log (form, reason, ip) VALUES (?, ?, ?)');
  const countUsers = db.prepare('SELECT COUNT(*) AS c FROM users');
  const countSpam = db.prepare('SELECT COUNT(*) AS c FROM spam_log');
  const lastUser = db.prepare('SELECT * FROM users ORDER BY id DESC LIMIT 1');
  const spamByReason = db.prepare('SELECT reason, COUNT(*) AS count FROM spam_log GROUP BY reason ORDER BY count DESC');
  return {
    addUser: (u) => insertUser.run(u.firstName, u.lastName, u.email, u.phone, u.country, hashPassword(u.password)),
    findByEmail: (email) => findByEmail.get(email),
    addForgot: (email) => insertForgot.run(email, Date.now()),
    forgotCount: (email, sinceMs) => countForgot.get(email, sinceMs).c,
    logSpam: (form, reason, ip) => insertSpam.run(form, reason, ip || null),
    stats: () => ({ users: countUsers.get().c, spam: countSpam.get().c }),
    lastUser: () => lastUser.get(),
    spamBreakdown: () => spamByReason.all().map((r) => ({ reason: r.reason, count: Number(r.count) })),
  };
}

module.exports = { open, makeRepo, hashPassword, verifyPassword, DUMMY_HASH };