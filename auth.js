/* =========================================================
   五惠成品檢驗紀錄分析系統 — 登入驗證
   ---------------------------------------------------------
   ・帳號清單在下方 USERS。密碼「不存明碼」，只存雜湊值：
       hash = SHA-256( salt + ":" + 帳號 + ":" + 密碼 )
   ・登入狀態存在 sessionStorage：關閉瀏覽器分頁即登出，
     另外超過 SESSION_HOURS 小時也會自動登出。
   ・注意：這是純前端的「門禁」，可擋一般人誤入，
     但無法防範懂技術的人（網站原始碼是公開的）。
   ========================================================= */
(function () {
  'use strict';

  // role: 'admin' = 系統管理員、'operator' = 操作人員
  const USERS = {
    adm0: { name: 'Jackie', role: 'admin',
            salt: '3b02e13d9812dd6c',
            hash: 'a53456084653fbf6936cf39db3720ffe9793b657cfc98bfbac2a2dc00214d918' },
    adm1: { name: 'Tommy', role: 'operator',
            salt: 'dff894fd3478c824',
            hash: '47142c5f1a5be7baa4f853ff3138f267782ba97e869201cc095ef8b4f650ab1b' }
  };
  const ROLE_LABEL = { admin: '系統管理員', operator: '操作人員' };
  const SESSION_KEY = 'pir_auth';
  const SESSION_HOURS = 8;

  // ---------- 登入狀態 ----------
  function getSession() {
    try {
      const s = JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null');
      if (!s || !USERS[s.user] || Date.now() > s.exp) return null;
      return s;
    } catch (e) { return null; }
  }
  function saveSession(user) {
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify({
        user: user, exp: Date.now() + SESSION_HOURS * 3600 * 1000
      }));
    } catch (e) { /* 無痕模式等情況存不了，就只在本頁有效 */ }
  }
  function clearSession() {
    try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
  }

  async function sha256(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ---------- 先把頁面藏起來，登入後才顯示 ----------
  const css = document.createElement('style');
  css.textContent = `
    html.auth-locked body > *:not(#auth-overlay){display:none !important;}
    #auth-overlay{position:fixed;inset:0;z-index:99999;background:#f0f2f8;
      display:flex;align-items:center;justify-content:center;padding:16px;
      font-family:'Microsoft JhengHei','PingFang TC',Arial,sans-serif;}
    #auth-overlay .auth-card{background:#fff;width:100%;max-width:360px;border-radius:10px;
      border:1px solid #dde1ee;padding:32px 28px;}
    #auth-overlay h2{font-size:18px;color:#283593;margin-bottom:4px;}
    #auth-overlay .auth-sub{font-size:12px;color:#6b6b80;margin-bottom:22px;}
    #auth-overlay label{display:block;font-size:13px;color:#1a1a2e;margin:12px 0 6px;}
    #auth-overlay input{width:100%;padding:10px 12px;font-size:14px;border:1px solid #c5cae9;
      border-radius:6px;outline:none;}
    #auth-overlay input:focus{border-color:#283593;}
    #auth-overlay button{width:100%;margin-top:22px;padding:11px;font-size:15px;color:#fff;
      background:#283593;border:none;border-radius:6px;cursor:pointer;}
    #auth-overlay button:disabled{opacity:.6;cursor:wait;}
    #auth-overlay .auth-err{min-height:18px;margin-top:12px;font-size:13px;color:#c62828;}
    .auth-user{margin-top:4px;font-size:13px;}
    .auth-user a{color:#fff;text-decoration:underline;cursor:pointer;margin-left:8px;}
  `;
  document.head.appendChild(css);

  const session = getSession();
  if (!session) document.documentElement.classList.add('auth-locked');

  // ---------- 登入畫面 ----------
  function showLogin() {
    const ov = document.createElement('div');
    ov.id = 'auth-overlay';
    ov.innerHTML = `
      <form class="auth-card" autocomplete="on">
        <h2>🏭 五惠成品檢驗紀錄分析系統</h2>
        <div class="auth-sub">請登入後使用</div>
        <label for="auth-id">帳號</label>
        <input id="auth-id" name="username" autocomplete="username" required>
        <label for="auth-pw">密碼</label>
        <input id="auth-pw" name="password" type="password" autocomplete="current-password" required>
        <button type="submit">登入</button>
        <div class="auth-err" id="auth-err"></div>
      </form>`;
    document.body.appendChild(ov);

    const form = ov.querySelector('form');
    const err = ov.querySelector('#auth-err');
    const btn = ov.querySelector('button');
    ov.querySelector('#auth-id').focus();

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      const id = ov.querySelector('#auth-id').value.trim();
      const pw = ov.querySelector('#auth-pw').value;
      const u = USERS[id];
      btn.disabled = true;
      err.textContent = '';
      const ok = u && (await sha256(u.salt + ':' + id + ':' + pw)) === u.hash;
      if (ok) {
        saveSession(id);
        ov.remove();
        document.documentElement.classList.remove('auth-locked');
        showUser(id);
      } else {
        // 稍微延遲，降低連續亂試的速度
        setTimeout(function () {
          err.textContent = '帳號或密碼錯誤';
          btn.disabled = false;
          ov.querySelector('#auth-pw').select();
        }, 800);
      }
    });
  }

  // ---------- 右上角顯示使用者 + 登出 ----------
  function showUser(id) {
    const u = USERS[id];
    const box = document.querySelector('.app-header .right');
    if (!box || document.querySelector('.auth-user')) return;
    const div = document.createElement('div');
    div.className = 'auth-user';
    div.innerHTML = `👤 ${u.name}（${ROLE_LABEL[u.role]}）<a id="auth-logout">登出</a>`;
    box.appendChild(div);
    div.querySelector('#auth-logout').addEventListener('click', function () {
      clearSession();
      location.reload();
    });
  }

  // 提供給其他程式判斷角色用，例如：if (window.AUTH && AUTH.isAdmin()) {...}
  window.AUTH = {
    user: function () { const s = getSession(); return s ? s.user : null; },
    isAdmin: function () { const s = getSession(); return !!s && USERS[s.user].role === 'admin'; }
  };

  document.addEventListener('DOMContentLoaded', function () {
    if (session) showUser(session.user);
    else showLogin();
  });
})();
