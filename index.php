<?php
declare(strict_types=1);
session_name('AUTHSID');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
session_start();

if (empty($_SESSION['authenticated'])) {
    header('Location: login.php', true, 302);
    exit;
}

if (empty($_SESSION['is_fallback']) && empty($_SESSION['is_guest'])) {
    $uid      = $_SESSION['user_id'] ?? '';
    $sessHash = $_SESSION['pwdhash'] ?? '';
    $valid    = false;

    $raw = @file_get_contents('/var/www/private/users.json');
    if ($raw !== false) {
        $json = json_decode($raw, true);
        foreach ($json['data'] ?? [] as $u) {
            if (($u['id'] ?? '') !== $uid) continue;
            $stored = $u['pwdhash'] ?? '';
            if ($stored !== '' && hash_equals(strtolower($stored), $sessHash)) {
                $valid = true;
            }
            break;
        }
    }

    if (!$valid) {
        session_unset();
        session_destroy();
        header('Location: login.php', true, 302);
        exit;
    }
}

session_write_close(); // SSE(ws.php)との並列接続時のセッションロック競合を防ぐ

require_once __DIR__ . '/nonce_helper.php';
$nonce = generate_nonce();
emit_csp($nonce, "'self' https://project.activetk.jp");

$username = htmlspecialchars($_SESSION['username'] ?? '', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, max-image-preview:none, max-video-preview:0, noimageindex, unavailable-after:Thu, 24 Nov 2022 00:00:00 +0900">
<title>ダッシュボード</title>
<link rel="stylesheet" href="styles/global.css" nonce="<?= $nonce ?>">
<script src="https://code.activetk.jp/archive-today.blocker.js" nonce="<?= $nonce ?>" defer></script>
<script nonce="<?= $nonce ?>">var _0x1e85d5=_0xac99;window.cp='cmswZXhuLnRhdHN1dC5qcA==',window.cpe='JUUzJTgxJTkzJUUzJTgxJUFFJUUzJTgyJUI1JUUzJTgyJUE0JUUzJTgzJTg4JUUzJTgxJUFGJUU2JTlDJUFDJUU2JTlEJUE1JUUzJTgxJUFFJUU2JTgzJUIzJUU1JUFFJTlBJUUzJTgxJUE4JUUzJTgxJUFGJUU5JTgxJTk1JUUzJTgxJTg2JUUzJTgxJUE3JUU0JUJEJUJGJUU3JTk0JUE4JUUzJTgxJTk1JUUzJTgyJThDJUUzJTgxJUE2JUUzJTgxJTg0JUUzJTgyJThCJUU1JThGJUFGJUU4JTgzJUJEJUU2JTgwJUE3JUUzJTgxJThDJUUzJTgxJTgyJUUzJTgyJThBJUUzJTgxJUJFJUUzJTgxJTk5JUUzJTgwJTgyJTNDYnIlM0UlRTYlOUMlQUMlRTYlOUQlQTUlRTMlODElQUUlRTMlODIlQjUlRTMlODIlQTQlRTMlODMlODglRTMlODElQUUlRTclQUUlQTElRTclOTAlODYlRTglODAlODUlRTMlODElQUIlRTklODAlQTMlRTclQjUlQTElRTMlODElOTclRTMlODElQTYlRTMlODElOEYlRTMlODElQTAlRTMlODElOTUlRTMlODElODQlRTMlODAlODIlM0NiciUzRSVFNiU5QyVBQyVFNiU5RCVBNSVFMyU4MSVBRSVFMyU4MiVCNSVFMyU4MiVBNCVFMyU4MyU4OCVFRiVCQyU5QWh0dHBzJTNBJTJGJTJGcmswZXhuLnRhdHN1dC5qcA==';function _0xac99(_0x3aecaa,_0x2e640e){var _0x40b52b=_0x40b5();return _0xac99=function(_0x15110b,_0x389c09){_0x15110b=_0x15110b-0xdb;var _0x3d0fc0=_0x40b52b[_0x15110b];return _0x3d0fc0;},_0xac99(_0x3aecaa,_0x2e640e);}(function(_0x28fef4,_0x507f58){var _0x4ba24d=_0xac99,_0x51bc4d=_0x28fef4();while(!![]){try{var _0x27b60a=-parseInt(_0x4ba24d(0xdf))/0x1*(parseInt(_0x4ba24d(0xdc))/0x2)+parseInt(_0x4ba24d(0xde))/0x3*(-parseInt(_0x4ba24d(0xe1))/0x4)+parseInt(_0x4ba24d(0xdd))/0x5*(-parseInt(_0x4ba24d(0xe2))/0x6)+parseInt(_0x4ba24d(0xe6))/0x7*(-parseInt(_0x4ba24d(0xe0))/0x8)+-parseInt(_0x4ba24d(0xe8))/0x9*(-parseInt(_0x4ba24d(0xea))/0xa)+-parseInt(_0x4ba24d(0xe4))/0xb*(parseInt(_0x4ba24d(0xe9))/0xc)+parseInt(_0x4ba24d(0xe3))/0xd;if(_0x27b60a===_0x507f58)break;else _0x51bc4d['push'](_0x51bc4d['shift']());}catch(_0x5ebc95){_0x51bc4d['push'](_0x51bc4d['shift']());}}}(_0x40b5,0x60f9d),document[_0x1e85d5(0xe5)](_0x1e85d5(0xdb),function(){var _0x3bc523=_0x1e85d5;decodeURIComponent(btoa(window['location'][_0x3bc523(0xeb)]))!=window['cp']&&document[_0x3bc523(0xe7)](decodeURIComponent(atob(window['cpe'])));}));function _0x40b5(){var _0x4b1445=['92540KSvSPW','host','DOMContentLoaded','6sYMyTb','5UgfKcP','3zOvJRz','169577bwQSBJ','8zOBdPB','2044716LSbUIz','1277808NtISmv','24526827gLoDvd','11KPkjdL','addEventListener','2096507BFeUPV','write','360GzcSBX','3926964FAHSEF'];_0x40b5=function(){return _0x4b1445;};return _0x40b5();}</script>
</head>
<body data-page="dashboard">
<div class="panel">
  <div class="panel-label">セッション有効</div>
  <h1><em>「</em>ダッシュボード<em>」</em></h1>

  <div class="status-grid">
    <div class="status-row">
      <span class="status-key">ステータス</span>
      <span class="status-val ok">認証済み</span>
    </div>
    <div class="status-row">
      <span class="status-key">ユーザー</span>
      <span class="status-val"><?= $username ?></span>
    </div>
  </div>

  <a class="btn btn-block" href="change_pwd.php">パスワード変更</a>
  <button class="btn-ghost" id="logoutBtn" type="button">ログアウト</button>
</div>

<script nonce="<?= $nonce ?>">
document.getElementById('logoutBtn').addEventListener('click', async function() {
  await fetch('action.php?logout=1', { credentials: 'same-origin' });
  location.href = 'login.php';
});
</script>
<script type="module" src="scripts/global.js" nonce="<?= $nonce ?>"></script>
</body>
</html>