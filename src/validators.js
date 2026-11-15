'use strict';
// Серверна валідація: allowlist-підхід (дозволяємо відоме, а не забороняємо відоме).

const NAME_RE = /^[\p{L}][\p{L}\s'’\-]{1,59}$/u;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
// Український формат: +380XXXXXXXXX (пробіли, дужки і дефіси прибираються до перевірки)
const PHONE_RE = /^\+380\d{9}$/;

// Країни, дозволені у списку. Значення з форми порівнюється з цим allowlist.
const COUNTRIES = ['UA', 'PL', 'DE', 'GB', 'US', 'OTHER'];

function normalize(value) {
  if (typeof value !== 'string') return '';
  return value.normalize('NFC').trim();
}

function normalizePhone(value) {
  return normalize(value).replace(/[\s()\-]/g, '');
}

function validateName(v, label = 'Імʼя') {
  if (!v) return `Вкажіть ${label.toLowerCase()}`;
  if (!NAME_RE.test(v)) return `${label}: 2–60 символів, лише літери, пробіл, апостроф, дефіс`;
  return null;
}

function validateEmail(v) {
  if (!v) return 'Вкажіть email';
  if (v.length > 254 || !EMAIL_RE.test(v)) return 'Некоректний формат email';
  return null;
}

function validatePhone(v) {
  if (!v) return 'Вкажіть телефон';
  if (!PHONE_RE.test(v)) return 'Телефон у форматі +380XXXXXXXXX';
  return null;
}

function validateCountry(v) {
  if (!COUNTRIES.includes(v)) return 'Оберіть країну зі списку';
  return null;
}

// Пароль: довжина важливіша за «складність» (рекомендація NIST SP 800-63B)
function validatePassword(v) {
  if (typeof v !== 'string' || !v) return 'Вкажіть пароль';
  if (v.length < 10) return 'Пароль має містити щонайменше 10 символів';
  if (v.length > 128) return 'Пароль занадто довгий (максимум 128 символів)';
  const common = ['1234567890', 'password12', 'qwertyuiop', '0987654321'];
  if (common.includes(v.toLowerCase())) return 'Цей пароль занадто поширений';
  if (!/\p{L}/u.test(v) || !/\d/.test(v)) return 'Пароль має містити літери та цифри';
  return null;
}

// При вході силу пароля не перевіряємо, лише тип і довжину
function validateLoginPassword(v) {
  if (typeof v !== 'string' || !v) return 'Вкажіть пароль';
  if (v.length > 128) return 'Пароль занадто довгий';
  return null;
}

// Мінімально допустимий час заповнення форми людиною (мс). Бот відправляє миттєво.
const MIN_FILL_MS = 2500;
const MAX_FORM_AGE_MS = 60 * 60 * 1000; // токен форми живе 1 годину

module.exports = {
  normalize,
  normalizePhone,
  validateName,
  validateEmail,
  validatePhone,
  validateCountry,
  validatePassword,
  validateLoginPassword,
  COUNTRIES,
  MIN_FILL_MS,
  MAX_FORM_AGE_MS,
};
