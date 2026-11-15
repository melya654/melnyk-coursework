'use strict';
// Клієнтська валідація — це зручність для користувача, а НЕ захист.
// Справжня перевірка завжди виконується на сервері (src/validators.js).

(function () {
  const NAME_RE = /^[\p{L}][\p{L}\s'’\-]{1,59}$/u;
  const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
  const PHONE_RE = /^\+380\d{9}$/;
  const COUNTRIES = ['UA', 'PL', 'DE', 'GB', 'US', 'OTHER'];

  const rules = {
    firstName: (v) => (!v ? 'Вкажіть імʼя' : !NAME_RE.test(v) ? 'Імʼя: 2–60 символів, лише літери, пробіл, апостроф, дефіс' : ''),
    lastName: (v) => (!v ? 'Вкажіть прізвище' : !NAME_RE.test(v) ? 'Прізвище: 2–60 символів, лише літери, пробіл, апостроф, дефіс' : ''),
    email: (v) => (!v ? 'Вкажіть email' : !EMAIL_RE.test(v) ? 'Некоректний формат email' : ''),
    phone: (v) => {
      const n = v.replace(/[\s()\-]/g, '');
      return !n ? 'Вкажіть телефон' : !PHONE_RE.test(n) ? 'Телефон у форматі +380XXXXXXXXX' : '';
    },
    country: (v) => (!COUNTRIES.includes(v) ? 'Оберіть країну зі списку' : ''),
    password: (v, form) => {
      if (!v) return 'Вкажіть пароль';
      if (form.dataset.endpoint === '/api/login') return '';
      return v.length < 10 ? 'Щонайменше 10 символів' : !/\p{L}/u.test(v) || !/\d/.test(v) ? 'Потрібні літери та цифри' : '';
    },
    passwordConfirm: (v, form) => (v !== form.elements.password.value ? 'Паролі не збігаються' : ''),
  };

  function showError(field, msg) {
    const box = document.getElementById(field.name + '-error');
    if (box) box.textContent = msg;
    if (msg) field.setAttribute('aria-invalid', 'true');
    else field.removeAttribute('aria-invalid');
  }

  function checkField(form, field) {
    const rule = rules[field.name];
    if (!rule) return '';
    const msg = rule(field.type === 'password' ? field.value : field.value.trim(), form);
    showError(field, msg);
    return msg;
  }

  async function getToken() {
    const r = await fetch('/api/form-token', { credentials: 'same-origin' });
    return (await r.json()).token;
  }

  function setStatus(box, kind, text) {
    box.className = 'status show ' + kind;
    box.textContent = text; // textContent, а не innerHTML — виключає XSS
  }

  const SUCCESS = {
    '/api/login': (data) => 'Вхід виконано' + (data.name ? ', ' + data.name : '') + '. Це демо: сесія не створюється.',
    '/api/signup': () => 'Акаунт створено. Перенаправляємо на сторінку входу…',
    '/api/forgot': () => 'Якщо такий акаунт існує, інструкцію буде надіслано. Це демо: лист не відправляється.',
  };

  function initForm(form) {
    const status = form.querySelector('.status');
    const submit = form.querySelector('button[type="submit"]');
    let token = '';
    getToken().then((t) => (token = t)).catch(() => {});

    form.setAttribute('novalidate', ''); // свої повідомлення замість браузерних

    // Перевірка при втраті фокусу й повторна перевірка під час виправлення
    form.querySelectorAll('input, select').forEach((f) => {
      if (!rules[f.name]) return;
      f.addEventListener('blur', () => checkField(form, f));
      f.addEventListener('input', () => {
        if (f.getAttribute('aria-invalid') === 'true') checkField(form, f);
      });
      f.addEventListener('change', () => checkField(form, f));
    });

    const pw = form.elements.password;
    const meter = form.querySelector('.meter > span');
    if (pw && meter) {
      pw.addEventListener('input', () => {
        const v = pw.value;
        let score = (Math.min(v.length, 16) / 16) * 60;
        if (/\p{L}/u.test(v) && /\d/.test(v)) score += 20;
        if (/[^\p{L}\d]/u.test(v)) score += 20;
        meter.style.width = Math.round(score) + '%';
        meter.style.background = score < 50 ? '#b3261e' : score < 80 ? '#b8860b' : '#1b6e3c';
      });
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      status.className = 'status';
      const fields = [...form.elements].filter((f) => rules[f.name]);
      const bad = fields.filter((f) => checkField(form, f));
      if (bad.length) {
        bad[0].focus();
        setStatus(status, 'bad', 'Виправте помилки у формі.');
        return;
      }
      const payload = {};
      new FormData(form).forEach((v, k) => (payload[k] = v));
      payload.formToken = token;
      submit.disabled = true;
      try {
        const r = await fetch(form.dataset.endpoint, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await r.json().catch(() => ({ ok: false, errors: { _form: 'Помилка сервера' } }));
        if (data.ok) {
          form.reset();
          form.querySelectorAll('[aria-invalid]').forEach((f) => f.removeAttribute('aria-invalid'));
          if (meter) meter.style.width = '0';
          const msg = SUCCESS[form.dataset.endpoint];
          setStatus(status, 'ok', msg ? msg(data) : 'Дані успішно надіслано.');
          // Після реєстрації повертаємо користувача на сторінку входу
          if (form.dataset.endpoint === '/api/signup') {
            setTimeout(() => { window.location.href = '/'; }, 1500);
          }
        } else {
          const errs = data.errors || {};
          for (const [name, msg] of Object.entries(errs)) {
            const f = form.elements[name];
            if (f && name !== '_form') showError(f, msg);
          }
          setStatus(status, 'bad', errs._form || 'Сервер відхилив дані. Перевірте поля.');
        }
      } catch {
        setStatus(status, 'bad', 'Немає звʼязку з сервером. Спробуйте пізніше.');
      } finally {
        submit.disabled = false;
        token = await getToken().catch(() => ''); // новий токен для наступної відправки
      }
    });
  }

  document.querySelectorAll('form[data-endpoint]').forEach(initForm);
})();