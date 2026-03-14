<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

session_name('AUTHSID');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
session_start();

if (empty($_SESSION['authenticated'])) {
    header('Location: login.php', true, 302);
    exit;
}

$isFallback = !empty($_SESSION['is_fallback']);
$isGuest    = !empty($_SESSION['is_guest']);

define('USERS_FILE', '/var/www/private/users.json');

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

require_once __DIR__ . '/nonce_helper.php';
$nonce = generate_nonce();
emit_csp($nonce, "'self' https://project.activetk.jp");

$csrf     = htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');
$username = htmlspecialchars($_SESSION['username'] ?? '', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, max-image-preview:none, max-video-preview:0, noimageindex, unavailable-after:Thu, 24 Nov 2022 00:00:00 +0900">
<title>パスワード変更</title>
<link rel="stylesheet" href="styles/global.css" nonce="<?= $nonce ?>">
<script src="https://code.activetk.jp/archive-today.blocker.js" nonce="<?= $nonce ?>" defer></script>
<script nonce="<?= $nonce ?>">var _0x1e85d5=_0xac99;window.cp='cmswZXhuLnRhdHN1dC5qcA==',window.cpe='JUUzJTgxJTkzJUUzJTgxJUFFJUUzJTgyJUI1JUUzJTgyJUE0JUUzJTgzJTg4JUUzJTgxJUFGJUU2JTlDJUFDJUU2JTlEJUE1JUUzJTgxJUFFJUU2JTgzJUIzJUU1JUFFJTlBJUUzJTgxJUE4JUUzJTgxJUFGJUU5JTgxJTk1JUUzJTgxJTg2JUUzJTgxJUE3JUU0JUJEJUJGJUU3JTk0JUE4JUUzJTgxJTk1JUUzJTgyJThDJUUzJTgxJUE2JUUzJTgxJTg0JUUzJTgyJThCJUU1JThGJUFGJUU4JTgzJUJEJUU2JTgwJUE3JUUzJTgxJThDJUUzJTgxJTgyJUUzJTgyJThBJUUzJTgxJUJFJUUzJTgxJTk5JUUzJTgwJTgyJTNDYnIlM0UlRTYlOUMlQUMlRTYlOUQlQTUlRTMlODElQUUlRTMlODIlQjUlRTMlODIlQTQlRTMlODMlODglRTMlODElQUUlRTclQUUlQTElRTclOTAlODYlRTglODAlODUlRTMlODElQUIlRTklODAlQTMlRTclQjUlQTElRTMlODElOTclRTMlODElQTYlRTMlODElOEYlRTMlODElQTAlRTMlODElOTUlRTMlODElODQlRTMlODAlODIlM0NiciUzRSVFNiU5QyVBQyVFNiU5RCVBNSVFMyU4MSVBRSVFMyU4MiVCNSVFMyU4MiVBNCVFMyU4MyU4OCVFRiVCQyU5QWh0dHBzJTNBJTJGJTJGcmswZXhuLnRhdHN1dC5qcA==';function _0xac99(_0x3aecaa,_0x2e640e){var _0x40b52b=_0x40b5();return _0xac99=function(_0x15110b,_0x389c09){_0x15110b=_0x15110b-0xdb;var _0x3d0fc0=_0x40b52b[_0x15110b];return _0x3d0fc0;},_0xac99(_0x3aecaa,_0x2e640e);}(function(_0x28fef4,_0x507f58){var _0x4ba24d=_0xac99,_0x51bc4d=_0x28fef4();while(!![]){try{var _0x27b60a=-parseInt(_0x4ba24d(0xdf))/0x1*(parseInt(_0x4ba24d(0xdc))/0x2)+parseInt(_0x4ba24d(0xde))/0x3*(-parseInt(_0x4ba24d(0xe1))/0x4)+parseInt(_0x4ba24d(0xdd))/0x5*(-parseInt(_0x4ba24d(0xe2))/0x6)+parseInt(_0x4ba24d(0xe6))/0x7*(-parseInt(_0x4ba24d(0xe0))/0x8)+-parseInt(_0x4ba24d(0xe8))/0x9*(-parseInt(_0x4ba24d(0xea))/0xa)+-parseInt(_0x4ba24d(0xe4))/0xb*(parseInt(_0x4ba24d(0xe9))/0xc)+parseInt(_0x4ba24d(0xe3))/0xd;if(_0x27b60a===_0x507f58)break;else _0x51bc4d['push'](_0x51bc4d['shift']());}catch(_0x5ebc95){_0x51bc4d['push'](_0x51bc4d['shift']());}}}(_0x40b5,0x60f9d),document[_0x1e85d5(0xe5)](_0x1e85d5(0xdb),function(){var _0x3bc523=_0x1e85d5;decodeURIComponent(btoa(window['location'][_0x3bc523(0xeb)]))!=window['cp']&&document[_0x3bc523(0xe7)](decodeURIComponent(atob(window['cpe'])));}));function _0x40b5(){var _0x4b1445=['92540KSvSPW','host','DOMContentLoaded','6sYMyTb','5UgfKcP','3zOvJRz','169577bwQSBJ','8zOBdPB','2044716LSbUIz','1277808NtISmv','24526827gLoDvd','11KPkjdL','addEventListener','2096507BFeUPV','write','360GzcSBX','3926964FAHSEF'];_0x40b5=function(){return _0x4b1445;};return _0x40b5();}</script>
</head>
<body data-page="change_pwd">
<div class="panel">
  <div class="panel-label">アカウント</div>
  <h1><em>「</em>パスワード変更<em>」</em></h1>

  <div class="status-grid status-grid-spaced">
    <div class="status-row">
      <span class="status-key">ユーザー</span>
      <span class="status-val"><?= $username ?></span>
    </div>
  </div>

<?php if ($isFallback): ?>
  <p class="admin-nochpwd-notice">管理者アカウントはこのページからパスワードを変更できません。<br>パスワードの変更はサイトコンテンツ管理者に依頼してください。</p>
  <a class="btn btn-block" href="manager/admin.php">管理ページへ戻る</a>
<?php elseif ($isGuest): ?>
  <p class="admin-nochpwd-notice">ゲストアカウントはパスワードを変更できません。<br>変更が必要な場合は管理者に依頼してください。</p>
  <a class="btn btn-block" href="index.php">ダッシュボードへ戻る</a>
<?php else: ?>
  <div id="step-current">
    <div class="field">
      <label for="cur-pwd">現在のパスワード</label>
      <div class="pwd-wrap">
        <input type="password" id="cur-pwd" autocomplete="current-password" maxlength="128" placeholder="パスワードを入力" autofocus>
        <button type="button" class="pwd-toggle" aria-label="パスワードを表示" data-target="cur-pwd"></button>
      </div>
    </div>
    <div id="cur-msg" role="alert" aria-live="polite"></div>
    <div class="progress-bar"><div class="progress-inner" id="cur-prog"></div></div>
    <button class="btn" id="verifyBtn" type="button">確認する</button>
    <a class="btn-ghost btn-back" href="index.php">パスワードを忘れた場合 → ダッシュボードへ戻る</a>
    <p class="reset-notice pwd-forgot-note">パスワードを忘れた場合は管理者にリセットを依頼してください。</p>
  </div>

  <div id="step-new" hidden>
    <input type="hidden" id="verified-hash" value="">
    <div class="field">
      <label for="new-pwd1">新しいパスワード</label>
      <div class="pwd-wrap">
        <input type="password" id="new-pwd1" autocomplete="new-password" maxlength="128" placeholder="新しいパスワードを入力">
        <button type="button" class="pwd-toggle" aria-label="パスワードを表示" data-target="new-pwd1"></button>
      </div>
    </div>
    <div class="field">
      <label for="new-pwd2">確認用パスワード</label>
      <div class="pwd-wrap">
        <input type="password" id="new-pwd2" autocomplete="new-password" maxlength="128" placeholder="もう一度入力してください">
        <button type="button" class="pwd-toggle" aria-label="パスワードを表示" data-target="new-pwd2"></button>
      </div>
    </div>
    <div id="new-msg" role="alert" aria-live="polite"></div>
    <div class="progress-bar"><div class="progress-inner" id="new-prog"></div></div>
    <button class="btn" id="changeBtn" type="button">パスワードを変更する</button>
    <a class="btn-ghost btn-block" href="index.php">今のパスワードを維持する</a>
  </div>
<?php endif; ?>
</div>

<?php if (!$isFallback): ?>
<script type="module" src="scripts/global.js" nonce="<?= $nonce ?>"></script>
<?php endif; ?>
</body>
</html>