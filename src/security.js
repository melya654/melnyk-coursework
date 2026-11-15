'use strict';
const crypto = require('node:crypto');
const { MIN_FILL_MS, MAX_FORM_AGE_MS } = require('./validators');

// Секрет для підпису токенів форми. У продакшні задається змінною середовища.
const SECRET = process.env.FORM_SECRET || crypto.randomBytes(32).toString('hex');

function sign(payload) {
  return crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
}

// Токен форми = час видачі + випадкове значення + HMAC-підпис.
// Дає одразу два захисти: CSRF (токен прив'язаний до cookie) і перевірку часу заповнення.
function issueFormToken(sessionId) {
  const issuedAt = Date.now();
  const nonce = crypto.randomBytes(8).toString('hex');
  const body = `${issuedAt}.${nonce}.${sessionId}`;
  return `${issuedAt}.${nonce}.${sign(body)}`;
}

function checkFormToken(token, sessionId, now = Date.now()) {
  if (typeof token !== 'string') return { ok: false, reason: 'token-missing' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'token-malformed' };
  const [issuedAtStr, nonce, mac] = parts;
  const expected = sign(`${issuedAtStr}.${nonce}.${sessionId}`);
  const a = Buffer.from(mac, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'token-invalid' };
  const age = now - Number(issuedAtStr);
  if (!Number.isFinite(age) || age < 0) return { ok: false, reason: 'token-invalid' };
  if (age < MIN_FILL_MS) return { ok: false, reason: 'too-fast' };
  if (age > MAX_FORM_AGE_MS) return { ok: false, reason: 'token-expired' };
  return { ok: true };
}

// Одноразовість токена: один токен = одна відправка. Повторне використання (replay) відхиляється.
// Сховище живе в памʼяті екземпляра сервера; запис зберігається, доки токен міг би бути чинним.
function createTokenStore(maxEntries = 10000) {
  const used = new Map(); // токен -> час, до якого його треба памʼятати
  return {
    consume(token, now = Date.now()) {
      for (const [t, exp] of used) {
        if (exp <= now) used.delete(t);
        else break; // записи додаються в хронологічному порядку
      }
      if (used.has(token)) return false;
      used.set(token, now + MAX_FORM_AGE_MS);
      if (used.size > maxEntries) used.delete(used.keys().next().value);
      return true;
    },
    size: () => used.size,
  };
}

// Honeypot: приховане поле, яке людина не бачить і не заповнює, а бот — заповнює.
function isHoneypotTripped(body) {
  return typeof body.website === 'string' && body.website.trim() !== '';
}

// Прості евристики спаму для текстових полів
const URL_RE = /(https?:\/\/|www\.)/gi;
// \b у JS не працює з кирилицею, тому межі слова задано через Unicode-lookaround
const SPAM_WORDS = /(?<![\p{L}\d])(viagra|casino|crypto\s*airdrop|bitcoin\s*doubler|кредит без відмови|казино|заробіток без вкладень)(?![\p{L}\d])/iu;

function looksLikeSpam(text) {
  if (!text) return null;
  const links = (text.match(URL_RE) || []).length;
  if (links > 2) return 'too-many-links';
  if (SPAM_WORDS.test(text)) return 'spam-keywords';
  if (/(.)\1{9,}/.test(text)) return 'repeated-chars';
  return null;
}

// Екранування для безпечного виведення в HTML (захист від XSS)
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = { issueFormToken, checkFormToken, createTokenStore, isHoneypotTripped, looksLikeSpam, escapeHtml };