'use strict';

const SVG_EYE_OPEN   = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="pwd-icon"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
const SVG_EYE_CLOSED = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="pwd-icon"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

export async function sha512hex(str) {
  const buf = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function initPwdToggles() {
  document.querySelectorAll('.pwd-toggle').forEach(btn => {
    btn.innerHTML = SVG_EYE_OPEN;
    btn.addEventListener('click', function () {
      const inp  = document.getElementById(this.dataset.target);
      const show = inp.type === 'password';
      inp.type       = show ? 'text' : 'password';
      this.innerHTML = show ? SVG_EYE_CLOSED : SVG_EYE_OPEN;
      this.setAttribute('aria-label', show ? 'パスワードを隠す' : 'パスワードを表示');
    });
  });
}

// ─── Proof of Work (Web Worker) ──────────────────────────────────────────────
// SHA-256(salt + ":" + nonce) の先頭 difficulty ビットが0になるnonceをWorkerで探す。
// Workerコードを Blob URL で生成することで外部ファイル不要。CSPに worker-src blob: が必要。
// メインスレッドはブロックされず、解決完了をPromiseで受け取る。
const POW_WORKER_SRC = `
self.onmessage = async ({ data: { salt, difficulty } }) => {
  const fullBytes = Math.floor(difficulty / 8);
  const remBits   = difficulty % 8;
  const enc       = new TextEncoder();
  for (let nonce = 0; nonce < 2 ** 32; nonce++) {
    const buf  = await crypto.subtle.digest('SHA-256', enc.encode(salt + ':' + nonce));
    const view = new Uint8Array(buf);
    let ok = true;
    for (let i = 0; i < fullBytes; i++) {
      if (view[i] !== 0) { ok = false; break; }
    }
    if (ok && remBits > 0 && (view[fullBytes] >> (8 - remBits)) !== 0) ok = false;
    if (ok) { self.postMessage({ nonce: nonce.toString() }); return; }
  }
  self.postMessage({ error: 'POW_EXHAUSTED' });
};
`;

function solvePoWInWorker(salt, difficulty) {
  return new Promise((resolve, reject) => {
    const blob   = new Blob([POW_WORKER_SRC], { type: 'text/javascript' });
    const url    = URL.createObjectURL(blob);
    const worker = new Worker(url);
    worker.onmessage = ({ data }) => {
      worker.terminate();
      URL.revokeObjectURL(url);
      data.error ? reject(new Error(data.error)) : resolve(data.nonce);
    };
    worker.onerror = (e) => {
      worker.terminate();
      URL.revokeObjectURL(url);
      reject(new Error('WORKER_ERROR: ' + e.message));
    };
    worker.postMessage({ salt, difficulty });
  });
}

class HttpError extends Error {
  constructor(status, code) { super(code); this.httpStatus = status; this.apiCode = code; }
}

async function fetchPoWToken() {
  const chalRes  = await fetch('action.php?pow_challenge=1', { credentials: 'same-origin' });
  const chalData = await chalRes.json();
  if (!chalData.ok) throw new HttpError(chalRes.status, 'POW_CHALLENGE_FAILED');

  const nonce = await solvePoWInWorker(chalData.salt, chalData.difficulty);

  const body = new URLSearchParams({ nonce });
  const res  = await fetch('action.php?pow_verify=1', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(), credentials: 'same-origin',
  });
  const data = await res.json();
  if (!data.ok) throw new HttpError(res.status, 'POW_VERIFY_FAILED');
  return data.pow_token;
}

// ─── RSA-2048 チャレンジ署名 ─────────────────────────────────────────────────
async function signWithRsaSha256(payload) {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-256' } },
    true, ['sign', 'verify']
  );
  const sigBuf  = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, new TextEncoder().encode(payload));
  const spkiBuf = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const toB64   = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  return { signature: toB64(sigBuf), clientPubkey: toB64(spkiBuf) };
}

async function authenticateWithChallenge(username, password, extraFields = {}) {
  const chalRes  = await fetch('action.php?challenge=1', { credentials: 'same-origin' });
  const chalData = await chalRes.json();
  if (!chalData.ok) throw new HttpError(chalRes.status, chalData.error || 'CHALLENGE_FAILED');

  const nonce   = chalData.nonce;
  const pwdhash = await sha512hex(password);
  const { signature, clientPubkey } = await signWithRsaSha256(nonce + ':' + pwdhash);

  const body = new URLSearchParams({
    username, pwdhash, nonce, signature, client_pubkey: clientPubkey,
    csrf_token: (document.cookie.match(/csrf_token=([^;]+)/) || [])[1] || '',
    ...extraFields,
  });
  const res  = await fetch('action.php', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(), credentials: 'same-origin',
  });
  const json = await res.json();
  return { httpStatus: res.status, ...json };
}

// ─── Long-pollingセッション監視 ──────────────────────────────────────────────
// authenticated pages (index, change_pwd) で呼び出す。
// force_logout を受信したら即座にセッションを破棄してリダイレクト。
// エラー時は指数バックオフで自動再試行する。
function startSessionWatch(logoutUrl = 'login.php') {
  const base    = location.pathname.includes('/manager/') ? '../ws.php' : 'ws.php';
  let dead      = false;
  let retries   = 0;
  let mtime     = 0;   // 最後に確認したusers.jsonのmtime
  let timer     = null;

  function forceLogout(reason) {
    if (dead) return;
    dead = true;
    if (timer) { clearTimeout(timer); timer = null; }
    const logoutPath = location.pathname.includes('/manager/') ? '../action.php?logout=1' : 'action.php?logout=1';
    fetch(logoutPath, { credentials: 'same-origin' }).finally(() => {
      location.href = logoutUrl + '?reason=' + encodeURIComponent(reason);
    });
  }

  async function poll() {
    if (dead) return;
    try {
      const res  = await fetch(`${base}?since=${mtime}`, { credentials: 'same-origin' });
      if (res.status === 401) { forceLogout('session_invalid'); return; }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      retries = 0;
      switch (data.event) {
        case 'force_logout': forceLogout(data.reason || 'session_invalid'); return;
        case 'session_ok':   mtime = data.mtime ?? mtime; break;
        case 'noop':         mtime = data.mtime ?? mtime; break;
      }
    } catch {
      // ネットワークエラー: 指数バックオフ（最大30秒）
      const delay = Math.min(1000 * (2 ** retries), 30000);
      retries++;
      timer = setTimeout(poll, delay);
      return;
    }
    if (!dead) timer = setTimeout(poll, 0);
  }

  // タブ非表示中は停止、復帰時に即再開
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (timer) { clearTimeout(timer); timer = null; }
    } else if (!dead) {
      if (timer) clearTimeout(timer);
      timer = setTimeout(poll, 0);
    }
  });

  poll();
}

// ─── ページ別エントリーポイント ───────────────────────────────────────────────
const page = document.body.dataset.page;

if (page === 'login') {
  initPwdToggles();

  const loginBtn = document.getElementById('loginBtn');
  const msgEl    = document.getElementById('msg');
  const progEl   = document.getElementById('prog');
  let busy = false;

  function setMsg(text, ok = false, eCode = '') {
    msgEl.className = ok ? 'ok' : (eCode ? 'err' : '');
    if (!eCode || ok) {
      msgEl.textContent = text;
      return;
    }
    msgEl.innerHTML = '';
    const span = document.createElement('span');
    span.textContent = text;
    const badge = document.createElement('code');
    badge.className   = 'err-code';
    badge.textContent = eCode;
    badge.title       = 'クリックしてコピー';
    badge.addEventListener('click', () => {
      navigator.clipboard.writeText(eCode).then(() => {
        badge.textContent = 'コピー済み';
        setTimeout(() => { badge.textContent = eCode; }, 1500);
      });
    });
    msgEl.append(span, ' ', badge);
  }

  // HTTPステータスとAPIエラーコードからE_xxxコードを解決する
  function resolveECode(httpStatus, apiError) {
    if (apiError?.startsWith('LOCKED:'))    return 'E_TOO_MANY_TRY';
    if (httpStatus === 401) {
      const map = {
        USER_CORRUPT:   'E_USER_KEY_BROKEN',
        GUEST_CORRUPT:  'E_GUEST_USER_KEY_BROKEN',
        GUEST_KEY_BROKEN: 'E_GUEST_GLOBAL_KEY_BROKEN',
      };
      return map[apiError] ?? 'E_PASSWORD_INVALID';
    }
    if (httpStatus === 403) return 'E_NET_DENIED';
    if (httpStatus === 429) return 'E_TOO_MANY_TRY';
    if (httpStatus === 503) return 'E_NET_SV_CRASH';
    if (httpStatus === 500) return 'E_NET_SV_ERR';
    if (httpStatus >= 500)  return 'E_NET_SV_ERR';
    if (httpStatus >= 400)  return 'E_NET_ERR';
    return 'E_UNDEFINED';
  }

  const eMsgMap = {
    E_PASSWORD_INVALID:        '認証に失敗しました',
    E_USER_KEY_BROKEN:         'アカウントが破損しています。管理者にリセットを依頼してください。',
    E_GUEST_USER_KEY_BROKEN:   'アカウントが破損しています。管理者に再設定を依頼してください。',
    E_GUEST_GLOBAL_KEY_BROKEN: 'ログインキーが破損しています。管理者に連絡してください。',
    E_TOO_MANY_TRY:            'ログイン試行回数が上限を超えました。しばらく待ってから再試行してください。',
    E_NET_DENIED:              'アクセスが拒否されました。',
    E_NET_ERR:                 'リクエストが拒否されました。',
    E_NET_SV_ERR:              'サーバーエラーが発生しました。',
    E_NET_SV_CRASH:            'サーバーが一時的に利用できません。しばらくしてから再試行してください。',
    E_UNDEFINED:               '不明なエラーが発生しました。',
  };

  const params = new URLSearchParams(location.search);
  if (params.get('reset') === 'done') {
    setMsg('パスワードを変更しました。新しいパスワードでログインしてください。', true);
  }
  const reasonMap = {
    integrity_failed: 'セッションが無効になりました。再ログインしてください。',
    session_expired:  'セッションの有効期限が切れました。',
    session_invalid:  'セッションが無効になりました。再ログインしてください。',
  };
  const reason = params.get('reason');
  if (reason && reasonMap[reason]) setMsg(reasonMap[reason]);

  async function doLogin() {
    if (busy) return;
    const uname = document.getElementById('uname').value.trim();
    const pwd   = document.getElementById('pwd').value;
    if (!uname || !pwd)    { setMsg('すべての項目を入力してください'); return; }
    if (uname.length > 24) { setMsg('ユーザー名が長すぎます');         return; }
    if (pwd.length  > 128) { setMsg('パスワードが長すぎます');         return; }

    busy = true;
    loginBtn.disabled  = true;
    progEl.style.width = '40%';
    setMsg('認証中\u2026');

    const extraFields = {};
    if (params.has('is_webmaster')) extraFields['is_webmaster'] = params.get('is_webmaster');
    if (params.has('user_id'))      extraFields['user_id']      = params.get('user_id');

    try {
      progEl.style.width = '30%';
      setMsg('PoW解決中…');
      const powToken = await fetchPoWToken();
      extraFields['pow_token'] = powToken;
      progEl.style.width = '70%';
      setMsg('認証中…');
      const data = await authenticateWithChallenge(uname, pwd, extraFields);
      progEl.style.width = '100%';
      if (data.ok) {
        setMsg('アクセスが許可されました', true);
        setTimeout(() => { location.href = data.redirect || 'index.php'; }, 500);
      } else {
        const apiErr = data.error || '';
        const eCode  = apiErr.startsWith('LOCKED:')
          ? (() => {
              const secs = parseInt(apiErr.split(':')[1], 10) || 60;
              setMsg('ログイン試行回数が上限を超えました — ' + secs + '秒間ロック中', false, 'E_TOO_MANY_TRY');
              return null;
            })()
          : resolveECode(data.httpStatus ?? 0, apiErr);
        if (eCode) setMsg(eMsgMap[eCode] ?? eMsgMap.E_UNDEFINED, false, eCode);
        progEl.style.width = '0';
        busy = false;
        loginBtn.disabled  = false;
      }
    } catch (err) {
      const httpSt = err instanceof HttpError ? err.httpStatus : 0;
      const eCode  = resolveECode(httpSt, err instanceof HttpError ? err.apiCode : '');
      setMsg(eMsgMap[eCode] ?? eMsgMap.E_UNDEFINED, false, eCode);
      progEl.style.width = '0';
      busy = false;
      loginBtn.disabled  = false;
    }
  }

  loginBtn.addEventListener('click', doLogin);
  document.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

  fetch('action.php?check=1', { credentials: 'same-origin' })
    .then(r => r.json())
    .then(d => { if (d.authenticated) location.href = d.redirect || 'index.php'; })
    .catch(() => {});
}

if (page === 'admin') {
  // ─── Long-polling admin_reload ───────────────────────────────────────────
  (function () {
    let dead          = false;
    let retries       = 0;
    let mtime         = 0;
    let timer         = null;
    let reloadPending = false;

    function bindConfirmButtons(root) {
      root.querySelectorAll('button[data-confirm-msg]').forEach(btn => {
        btn.addEventListener('click', function (e) {
          if (!confirm(this.dataset.username + ' ' + this.dataset.confirmMsg)) {
            e.preventDefault();
          }
        });
      });
    }

    function updateCsrf(newCsrf) {
      document.querySelectorAll('input[name="csrf_token"]').forEach(el => {
        el.value = newCsrf;
      });
    }

    async function doPartialReload() {
      if (reloadPending) return;
      reloadPending = true;
      try {
        const res  = await fetch('admin.php?partial=table', { credentials: 'same-origin' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        if (!data.ok) throw new Error('partial_failed');
        const main = document.querySelector('.admin-main');
        if (!main) throw new Error('no_admin_main');
        const oldTable = main.querySelector('table');
        if (oldTable) {
          const tmp = document.createElement('div');
          tmp.innerHTML = data.html;
          const newTable = tmp.querySelector('table');
          if (newTable) {
            oldTable.replaceWith(newTable);
            bindConfirmButtons(newTable);
          }
        }
        if (data.csrf) updateCsrf(data.csrf);
        if (location.search) history.replaceState(null, '', location.pathname);
      } catch {
        history.replaceState(null, '', location.pathname);
        location.reload();
        return;
      }
      reloadPending = false;
    }

    async function poll() {
      if (dead) return;
      try {
        const res  = await fetch(`../ws.php?since=${mtime}`, { credentials: 'same-origin' });
        if (res.status === 401) {
          dead = true;
          fetch('../action.php?logout=1', { credentials: 'same-origin' }).finally(() => {
            location.href = '../login.php?reason=session_invalid';
          });
          return;
        }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        retries = 0;
        switch (data.event) {
          case 'admin_reload':
            mtime = data.mtime ?? mtime;
            doPartialReload();
            break;
          case 'force_logout':
            dead = true;
            fetch('../action.php?logout=1', { credentials: 'same-origin' }).finally(() => {
              location.href = '../login.php?reason=' + encodeURIComponent(data.reason || 'session_invalid');
            });
            return;
          case 'noop':
            mtime = data.mtime ?? mtime;
            break;
        }
      } catch {
        const delay = Math.min(1000 * (2 ** retries), 30000);
        retries++;
        timer = setTimeout(poll, delay);
        return;
      }
      if (!dead) timer = setTimeout(poll, 0);
    }

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        if (timer) { clearTimeout(timer); timer = null; }
      } else if (!dead) {
        if (timer) clearTimeout(timer);
        timer = setTimeout(poll, 0);
      }
    });

    poll();
  })();

  // ─── URLパラメーター除去（初期表示時） ──────────────────────────────────
  if (location.search) {
    history.replaceState(null, '', location.pathname);
  }

  // ─── コピーボタン ────────────────────────────────────────────────────────
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', async function () {
      const text = this.dataset.copy;
      try {
        await navigator.clipboard.writeText(text);
        const orig = this.textContent;
        this.textContent = 'コピー済';
        setTimeout(() => { this.textContent = orig; }, 2000);
      } catch {
        prompt('URLをコピーしてください:', text);
      }
    });
  });

  // ─── PC判定 ────────────────────────────────────────────────────────────────
  // 多段階判定: PHP UAチェック済みの場合でもJS側で補完する
  //
  // PCと判定する条件（いずれかが成立すればPC扱い）:
  //   - pointer:fine（マウス主体）かつ maxTouchPoints===0
  //   - 論理画面幅 >= 1024px かつ pointer:fine
  //   - UA Client Hints で mobile===false（DeX/PCモード含む）
  //
  // モバイルと判定する条件（AND）:
  //   - pointer:coarse または maxTouchPoints > 0
  //   - かつ 論理画面幅 < 1024
  //   - かつ UA Client Hints で mobile===true（取得できた場合）

  async function detectMobile() {
    // UA Client Hints（Chrome/Edge/Android Chrome対応）
    // DeX・PCモードのAndroidはここで mobile=false を返す
    if (navigator.userAgentData) {
      try {
        const hint = await navigator.userAgentData.getHighEntropyValues(['mobile', 'platform']);
        if (hint.mobile === false) return false; // PCモード確定
        if (hint.mobile === true) {
          // mobile=true でも一応pointer/幅で補完
          const fine   = window.matchMedia('(pointer: fine)').matches;
          const logicalW = window.screen.width / (window.devicePixelRatio || 1);
          if (fine && logicalW >= 1024) return false; // PCキーボード接続等
          return true;
        }
      } catch {}
    }

    // UA Client Hints 非対応ブラウザ（Safari等）
    const fine     = window.matchMedia('(pointer: fine)').matches;
    const coarse   = window.matchMedia('(pointer: coarse)').matches;
    const hasTouch = navigator.maxTouchPoints > 0;
    const logicalW = window.screen.width / (window.devicePixelRatio || 1);

    // pointer:fine かつ タッチなし → PC確定
    if (fine && !hasTouch) return false;
    // pointer:fine かつ 論理幅>=1024 → タッチ付きノートPCを許容
    if (fine && logicalW >= 1024) return false;
    // pointer:coarse かつ 論理幅<1024 → モバイル
    if (coarse && logicalW < 1024) return true;

    return false; // 判定不能はPC扱い（管理者が意図的にアクセスしている可能性）
  }

  detectMobile().then(isMobile => {
    if (isMobile) document.body.classList.add('is-mobile');
  });

  initPwdToggles();

  document.querySelectorAll('button[data-confirm-msg]').forEach(btn => {
    btn.addEventListener('click', function (e) {
      if (!confirm(this.dataset.username + ' ' + this.dataset.confirmMsg)) {
        e.preventDefault();
      }
    });
  });

  document.getElementById('addForm').addEventListener('submit', async function (e) {
    e.preventDefault();
    const pwd = document.getElementById('apwd').value;
    if (!pwd)           { alert('パスワードを入力してください'); return; }
    if (pwd.length < 8) { alert('パスワードは8文字以上で入力してください'); return; }
    document.getElementById('pwdhash').value = await sha512hex(pwd);
    this.submit();
  });
}

if (page === 'reset') {
  initPwdToggles();

  const form = document.getElementById('setForm');
  if (form) {
    const setBtn = document.getElementById('setBtn');
    const prog   = document.getElementById('prog');
    let busy = false;

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      if (busy) return;
      const p1 = document.getElementById('pwd1').value;
      const p2 = document.getElementById('pwd2').value;
      if (!p1)           { alert('パスワードを入力してください。'); return; }
      if (p1.length < 8) { alert('8文字以上で入力してください。');  return; }
      if (p1 !== p2)     { alert('パスワードが一致しません。');     return; }
      busy = true;
      setBtn.disabled    = true;
      prog.style.width   = '60%';
      document.getElementById('pwdhash').value = await sha512hex(p1);
      prog.style.width   = '100%';
      form.submit();
    });
  }
}

if (page === 'change_pwd') {
  initPwdToggles();
  startSessionWatch('login.php');

  const stepCurrent = document.getElementById('step-current');
  const stepNew     = document.getElementById('step-new');
  const verifyBtn   = document.getElementById('verifyBtn');
  const changeBtn   = document.getElementById('changeBtn');
  const curMsg      = document.getElementById('cur-msg');
  const curProg     = document.getElementById('cur-prog');
  const newMsg      = document.getElementById('new-msg');
  const newProg     = document.getElementById('new-prog');

  function setCurMsg(text, ok = false) { curMsg.textContent = text; curMsg.className = ok ? 'ok' : ''; }
  function setNewMsg(text, ok = false) { newMsg.textContent = text; newMsg.className = ok ? 'ok' : ''; }

  if (verifyBtn !== null) {
    verifyBtn.addEventListener('click', async function () {
      const pwd = document.getElementById('cur-pwd').value;
      if (!pwd) { setCurMsg('パスワードを入力してください'); return; }
      verifyBtn.disabled  = true;
      curProg.style.width = '40%';
      setCurMsg('確認中…');
      try {
        const chalRes  = await fetch('action.php?change_pwd_challenge=1', { credentials: 'same-origin' });
        const chalData = await chalRes.json();
        if (!chalData.ok) throw new Error(chalData.error || 'CHALLENGE_FAILED');
        const nonce   = chalData.nonce;
        const pwdhash = await sha512hex(pwd);
        const { signature, clientPubkey } = await signWithRsaSha256(nonce + ':' + pwdhash);
        curProg.style.width = '70%';
        const body = new URLSearchParams({
          mode: 'verify_current', pwdhash, nonce, signature, client_pubkey: clientPubkey,
          csrf_token: (document.cookie.match(/csrf_token=([^;]+)/) || [])[1] || '',
        });
        const res  = await fetch('action.php?change_pwd=1', {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: body.toString(), credentials: 'same-origin',
        });
        const data = await res.json();
        curProg.style.width = '100%';
        if (data.ok) {
          document.getElementById('verified-hash').value = data.step_token;
          stepCurrent.hidden = true;
          stepNew.hidden     = false;
          document.getElementById('new-pwd1').focus();
        } else {
          const err = data.error || '';
          setCurMsg(err === 'WRONG_CURRENT_PASSWORD' ? '現在のパスワードが違います' : err);
          curProg.style.width = '0';
          verifyBtn.disabled  = false;
        }
      } catch {
        setCurMsg('ネットワークエラーが発生しました');
        curProg.style.width = '0';
        verifyBtn.disabled  = false;
      }
    });
  }

  if (changeBtn !== null) {
    changeBtn.addEventListener('click', async function () {
      const p1 = document.getElementById('new-pwd1').value;
      const p2 = document.getElementById('new-pwd2').value;
      if (!p1)           { setNewMsg('パスワードを入力してください'); return; }
      if (p1.length < 8) { setNewMsg('8文字以上で入力してください'); return; }
      if (p1 !== p2)     { setNewMsg('パスワードが一致しません');    return; }
      changeBtn.disabled  = true;
      newProg.style.width = '60%';
      setNewMsg('変更中…');
      try {
        const newHash   = await sha512hex(p1);
        const stepToken = document.getElementById('verified-hash').value;
        newProg.style.width = '90%';
        const body = new URLSearchParams({
          mode: 'set_new', new_pwdhash: newHash, step_token: stepToken,
          csrf_token: (document.cookie.match(/csrf_token=([^;]+)/) || [])[1] || '',
        });
        const res  = await fetch('action.php?change_pwd=1', {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: body.toString(), credentials: 'same-origin',
        });
        const data = await res.json();
        newProg.style.width = '100%';
        if (data.ok) {
          setNewMsg('パスワードを変更しました', true);
          setTimeout(() => { location.href = 'index.php'; }, 1000);
        } else {
          const err = data.error || '';
          setNewMsg(err === 'SAME_AS_CURRENT' ? '現在と同じパスワードは使用できません' : err);
          newProg.style.width = '0';
          changeBtn.disabled  = false;
        }
      } catch {
        setNewMsg('ネットワークエラーが発生しました');
        newProg.style.width = '0';
        changeBtn.disabled  = false;
      }
    });
  }
}

if (page === 'dashboard') {
  startSessionWatch('login.php');
}