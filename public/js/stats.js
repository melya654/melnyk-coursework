'use strict';
// Сторінка статистики: дані беруться з /api/stats, виводяться через textContent (без XSS).

(function () {
  // Пояснення причин блокування (ключі збігаються з тим, що пише сервер у spam_log)
  const REASONS = {
    honeypot: ['Honeypot', 'приховане поле, яке заповнюють лише боти'],
    'too-fast': ['Швидка відправка', 'форму надіслано швидше ніж за 2,5 с'],
    'token-missing': ['Немає токена', 'запит без токена форми (CSRF)'],
    'token-malformed': ['Некоректний токен', 'токен має неправильну структуру'],
    'token-invalid': ['Підроблений токен', 'підпис токена не збігається'],
    'token-expired': ['Прострочений токен', 'форма відкрита понад годину'],
    'token-reused': ['Повторний токен', 'токен форми вже використано (replay)'],
    'disposable-email': ['Тимчасовий email', 'реєстрація з одноразової пошти'],
    'rate-limit': ['Ліміт запитів', 'забагато відправок з однієї IP за хвилину'],
    'email-throttle': ['Ліміт на адресу', 'понад 3 запити відновлення на email за годину'],
    'too-many-links': ['Багато посилань', 'у тексті понад 2 посилання'],
    'spam-keywords': ['Спам-слова', 'у тексті є типові спам-фрази'],
    'repeated-chars': ['Повтори символів', 'підозріла послідовність однакових символів'],
  };

  function cell(text) {
    const td = document.createElement('td');
    td.textContent = text;
    return td;
  }

  async function load() {
    const body = document.getElementById('stats-body');
    const note = document.getElementById('stats-note');
    try {
      const r = await fetch('/api/stats', { credentials: 'same-origin' });
      const data = await r.json();
      document.getElementById('total-users').textContent = String(data.users);
      document.getElementById('total-blocked').textContent = String(data.spam);
      body.textContent = '';
      if (!data.blocked.length) {
        const tr = document.createElement('tr');
        const td = cell('Заблокованих спроб поки немає');
        td.colSpan = 3;
        tr.appendChild(td);
        body.appendChild(tr);
      }
      for (const row of data.blocked) {
        const info = REASONS[row.reason] || [row.reason, 'інша причина'];
        const tr = document.createElement('tr');
        tr.append(cell(info[0]), cell(info[1]), cell(String(row.count)));
        body.appendChild(tr);
      }
      note.textContent = 'Дані оновлюються при відкритті сторінки. На Vercel лічильники скидаються при перезапуску сервера.';
    } catch {
      note.textContent = 'Не вдалося завантажити статистику.';
    }
  }

  load();
})();