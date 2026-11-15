'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/server');
const S = require('../src/security');
const { hashPassword, verifyPassword } = require('../src/db');

const SID = 'a'.repeat(32);
let server, base, app;

// Токен «видано 5 секунд тому», щоб пройти перевірку мінімального часу заповнення
function oldToken(sid = SID, ageMs = 5000) {
  const real = Date.now;
  Date.now = () => real() - ageMs;
  try {
    return S.issueFormToken(sid);
  } finally {
    Date.now = real;
  }
}

async function post(path, body, { sid = SID, raw } = {}) {
  const r = await fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: `sid=${sid}` },
    body: raw !== undefined ? raw : JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => null) };
}

let counter = 0;
const goodSignup = (over = {}) => ({
  firstName: 'Андрій',
  lastName: 'Мельник',
  email: `user${++counter}@example.com`,
  phone: '+380 50 123 45 67',
  country: 'UA',
  password: 'Strong-pass-2026',
  passwordConfirm: 'Strong-pass-2026',
  website: '',
  formToken: oldToken(),
  ...over,
});

before(async () => {
  app = createApp({ dbFile: ':memory:', rateLimit: 1000 });
  await new Promise((res) => (server = app.listen(0, res)));
  base = `http://localhost:${server.address().port}`;
});
after(() => server.close());

// ---------- Реєстрація: валідація ----------

test('коректна реєстрація приймається, телефон нормалізується, пароль хешується', async () => {
  const body = goodSignup();
  const r = await post('/api/signup', body);
  assert.equal(r.status, 200);
  const u = app.repo.lastUser();
  assert.equal(u.phone, '+380501234567');
  assert.ok(u.password_hash.startsWith('scrypt$'));
  assert.ok(!u.password_hash.includes(body.password));
});

test('порожні та некоректні поля відхиляються з 422', async () => {
  const r = await post('/api/signup', goodSignup({ firstName: '', lastName: '1', email: 'not-an-email', phone: '123', country: '' }));
  assert.equal(r.status, 422);
  assert.deepEqual(Object.keys(r.json.errors).sort(), ['country', 'email', 'firstName', 'lastName', 'phone']);
});

test('країна лише зі списку (підміна значення select відхиляється)', async () => {
  const r = await post('/api/signup', goodSignup({ country: 'Atlantis' }));
  assert.equal(r.status, 422);
  assert.ok(r.json.errors.country);
});

test('слабкий пароль і розбіжність паролів', async () => {
  const r = await post('/api/signup', goodSignup({ password: 'short', passwordConfirm: 'other' }));
  assert.equal(r.status, 422);
  assert.ok(r.json.errors.password && r.json.errors.passwordConfirm);
  const common = await post('/api/signup', goodSignup({ password: 'qwertyuiop', passwordConfirm: 'qwertyuiop' }));
  assert.equal(common.status, 422);
});

test('дубль email не створює другий акаунт', async () => {
  const email = 'dup@example.com';
  assert.equal((await post('/api/signup', goodSignup({ email }))).status, 200);
  assert.equal((await post('/api/signup', goodSignup({ email: 'DUP@Example.com' }))).status, 409);
});

test('нестрокові значення (масиви, обʼєкти, числа) не ламають сервер', async () => {
  const r = await post('/api/signup', goodSignup({ firstName: ['a', 'b'], email: { $ne: '' }, phone: 5, country: {} }));
  assert.equal(r.status, 422);
});

// ---------- Ін'єкції ----------

test('XSS-вектор в імені не проходить allowlist-валідацію', async () => {
  const r = await post('/api/signup', goodSignup({ firstName: '<script>alert(1)</script>' }));
  assert.equal(r.status, 422);
  assert.ok(r.json.errors.firstName);
  assert.equal(S.escapeHtml('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
});

test("SQL-ін'єкція в email і імені відхиляється, база жива", async () => {
  const before = app.repo.stats().users;
  const r = await post('/api/signup', goodSignup({ firstName: "Robert'); DROP TABLE users;--" }));
  assert.equal(r.status, 422);
  const login = await post('/api/login', { email: "' OR '1'='1", password: 'x', website: '', formToken: oldToken() });
  assert.equal(login.status, 422); // не email, відхилено ще до запиту в базу
  assert.equal(app.repo.stats().users, before);
});

// ---------- Вхід ----------

test('вхід: правильні дані приймаються', async () => {
  const body = goodSignup({ email: 'login@example.com' });
  await post('/api/signup', body);
  const r = await post('/api/login', { email: 'login@example.com', password: body.password, website: '', formToken: oldToken() });
  assert.equal(r.status, 200);
  assert.equal(r.json.name, 'Андрій');
});

test('вхід: однакова відповідь для невірного пароля і неіснуючого email', async () => {
  const body = goodSignup({ email: 'known@example.com' });
  await post('/api/signup', body);
  const wrongPass = await post('/api/login', { email: 'known@example.com', password: 'wrong-password-1', website: '', formToken: oldToken() });
  const noUser = await post('/api/login', { email: 'nobody@example.com', password: 'wrong-password-1', website: '', formToken: oldToken() });
  assert.equal(wrongPass.status, 401);
  assert.equal(noUser.status, 401);
  assert.deepEqual(wrongPass.json, noUser.json);
});

// ---------- Відновлення пароля ----------

test('відновлення: відповідь однакова для існуючого і неіснуючого email', async () => {
  await post('/api/signup', goodSignup({ email: 'exists@example.com' }));
  const a = await post('/api/forgot', { email: 'exists@example.com', website: '', formToken: oldToken() });
  const b = await post('/api/forgot', { email: 'ghost@example.com', website: '', formToken: oldToken() });
  assert.equal(a.status, 200);
  assert.deepEqual(a.json, b.json);
});

test('відновлення: некоректний email відхиляється', async () => {
  const r = await post('/api/forgot', { email: 'bad', website: '', formToken: oldToken() });
  assert.equal(r.status, 422);
});

test('відновлення: після 3 запитів на адресу нові не реєструються (антиспам)', async () => {
  const email = 'bombed@example.com';
  for (let i = 0; i < 6; i++) {
    const r = await post('/api/forgot', { email, website: '', formToken: oldToken() });
    assert.equal(r.status, 200); // відповідь однакова, але запити поза лімітом ігноруються
  }
  const spamBefore = app.repo.stats().spam;
  await post('/api/forgot', { email, website: '', formToken: oldToken() });
  assert.equal(app.repo.stats().spam, spamBefore + 1);
  assert.equal(app.repo.forgotCount(email, 0), 3);
});

// ---------- Антиспам ----------

test('honeypot: бот отримує «успіх», але акаунт не створюється', async () => {
  const before = app.repo.stats();
  const r = await post('/api/signup', goodSignup({ website: 'http://spam.example' }));
  assert.equal(r.status, 200);
  assert.equal(app.repo.stats().users, before.users);
  assert.equal(app.repo.stats().spam, before.spam + 1);
});

test('занадто швидка відправка блокується', async () => {
  const r = await post('/api/signup', goodSignup({ formToken: oldToken(SID, 100) }));
  assert.equal(r.status, 429);
});

test('відсутній, підроблений і чужий токен відхиляються (CSRF)', async () => {
  const noToken = goodSignup();
  delete noToken.formToken;
  assert.equal((await post('/api/signup', noToken)).status, 403);
  assert.equal((await post('/api/signup', goodSignup({ formToken: 'x.y.z' }))).status, 403);
  assert.equal((await post('/api/signup', goodSignup({ formToken: oldToken('b'.repeat(32)) }))).status, 403);
});

test('прострочений токен відхиляється', async () => {
  const r = await post('/api/signup', goodSignup({ formToken: oldToken(SID, 2 * 60 * 60 * 1000) }));
  assert.equal(r.status, 403);
});

test('rate limiting: після ліміту відповідь 429', async () => {
  const a = createApp({ dbFile: ':memory:', rateLimit: 3 });
  const s = await new Promise((res) => {
    const x = a.listen(0, () => res(x));
  });
  const url = `http://localhost:${s.address().port}/api/forgot`;
  const codes = [];
  for (let i = 0; i < 5; i++) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: `sid=${SID}` },
      body: JSON.stringify({ email: 'a@example.com', website: '', formToken: oldToken() }),
    });
    codes.push(r.status);
  }
  s.close();
  assert.deepEqual(codes, [200, 200, 200, 429, 429]);
});

// ---------- Некоректні запити та заголовки ----------

test('занадто великий і некоректний JSON обробляються без падіння', async () => {
  const big = await post('/api/signup', null, { raw: JSON.stringify({ firstName: 'x'.repeat(20000) }) });
  assert.equal(big.status, 413);
  const broken = await post('/api/signup', null, { raw: '{not json' });
  assert.equal(broken.status, 400);
});

test('паролі: scrypt з сіллю, однаковий пароль дає різні хеші', () => {
  const h1 = hashPassword('abc12345678');
  const h2 = hashPassword('abc12345678');
  assert.notEqual(h1, h2);
  assert.ok(verifyPassword('abc12345678', h1));
  assert.ok(!verifyPassword('wrong', h1));
});

test('заголовки безпеки та cookie', async () => {
  const r = await fetch(base + '/api/form-token');
  assert.ok(r.headers.get('content-security-policy').includes("script-src 'self'"));
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-powered-by'), null);
  const cookie = r.headers.get('set-cookie');
  assert.ok(/HttpOnly/i.test(cookie) && /SameSite=Strict/i.test(cookie));
});
