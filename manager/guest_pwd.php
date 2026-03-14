<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// ─── フォームPOST向けBot対策フィルタ ──────────────────────────────────────────
$_ua      = $_SERVER['HTTP_USER_AGENT']      ?? '';
$_accEnc  = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
$_accLng  = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
$_secMode = $_SERVER['HTTP_SEC_FETCH_MODE']  ?? '';
$_secSite = $_SERVER['HTTP_SEC_FETCH_SITE']  ?? '';
$_secDest = $_SERVER['HTTP_SEC_FETCH_DEST']  ?? '';
$_origin  = $_SERVER['HTTP_ORIGIN']          ?? '';
$_host    = $_SERVER['HTTP_HOST']            ?? '';

if ($_ua === '' || $_accEnc === '' || $_accLng === '') { http_response_code(403); exit; }
if (preg_match('/^(curl|python|go-http|java|ruby|perl|php|axios|got|node-fetch|okhttp|libwww)/i', $_ua)) {
    http_response_code(403); exit;
}
if (stripos($_accEnc, 'gzip') === false) { http_response_code(403); exit; }
if ($_secMode !== '' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!($_secMode === 'navigate' && $_secSite === 'same-origin' && $_secDest === 'document')) {
        http_response_code(403); exit;
    }
}
if ($_secMode !== '' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    if (!($_secMode === 'navigate' || $_secMode === 'same-origin')) { http_response_code(403); exit; }
}
if ($_origin !== '' && parse_url($_origin, PHP_URL_HOST) !== $_host) { http_response_code(403); exit; }
unset($_ua, $_accEnc, $_accLng, $_secMode, $_secSite, $_secDest, $_origin, $_host);

session_name('AUTHSID');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
session_start();

if (empty($_SESSION['authenticated']) || empty($_SESSION['is_fallback'])) {
    header('Location: ../login.php', true, 302); exit;
}
$now = time();
if ((int)($_SESSION['login_at'] ?? 0) <= 0 || ($now - (int)($_SESSION['login_at'] ?? 0)) > 900) {
    session_unset(); session_destroy();
    header('Location: ../login.php', true, 302); exit;
}
if ((int)($_SESSION['last_activity'] ?? 0) > 0 && ($now - (int)($_SESSION['last_activity'] ?? 0)) > 300) {
    session_unset(); session_destroy();
    header('Location: ../login.php?reason=session_expired', true, 302); exit;
}
$_SESSION['last_activity'] = $now;
session_regenerate_id(true);
$uaHash = hash('sha256',
    ($_SERVER['HTTP_USER_AGENT']      ?? '') .
    ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '') .
    ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '')
);
if (isset($_SESSION['_ua']) && !hash_equals($_SESSION['_ua'], $uaHash)) {
    session_unset(); session_destroy();
    header('Location: ../login.php', true, 302); exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

require_once __DIR__ . '/../guest_helper.php';

// GET: ゲストIDをURLから受け取りフォーム表示
// POST: パスワード更新
$guestId = $_GET['id'] ?? ($_POST['id'] ?? '');
if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $guestId)) {
    header('Location: admin.php?msg=err_notfound', true, 302); exit;
}

$guests = load_guests();
$target = null;
foreach ($guests as $g) {
    if (($g['id'] ?? '') === $guestId) { $target = $g; break; }
}
if ($target === null) {
    header('Location: admin.php?msg=err_notfound', true, 302); exit;
}

$error   = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $cl = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($cl > 4096) { http_response_code(413); exit; }

    $tok = $_POST['csrf_token'] ?? '';
    if (!is_string($tok) || !hash_equals($_SESSION['csrf_token'], $tok)) {
        http_response_code(403); exit('CSRF_ERROR');
    }

    $newPwd = $_POST['new_password'] ?? '';
    if (strlen($newPwd) < PWD_MIN_LEN || strlen($newPwd) > 128) {
        $error = PWD_MIN_LEN . '文字以上128文字以下で入力してください。';
    } else {
        foreach ($guests as &$g) {
            if (($g['id'] ?? '') !== $guestId) continue;
            $g['enc_pwd']       = guest_encrypt($newPwd);
            $g['session_token'] = null;
            break;
        }
        unset($g);
        if (save_guests($guests)) {
            error_log(sprintf('ADMIN_CHANGE_GUEST_PWD admin=%s guest=%s',
                $_SESSION['username'] ?? '', $target['name'] ?? ''));
            $success = true;
        } else {
            $error = '保存に失敗しました。';
        }
    }
}

$csrf        = htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');
session_write_close();

require_once __DIR__ . '/../nonce_helper.php';
$nonce     = generate_nonce();
emit_csp($nonce, "'self'");
$guestName = htmlspecialchars($target['name'] ?? '', ENT_QUOTES, 'UTF-8');
$guestIdH  = htmlspecialchars($guestId, ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>ゲストパスワード変更</title>
<link rel="stylesheet" href="../styles/global.css" nonce="<?= $nonce ?>">
</head>
<body data-page="change_pwd">
<div class="panel">
  <div class="panel-label">ゲスト管理</div>
  <h1><em>「</em>パスワード変更<em>」</em></h1>

  <div class="status-grid status-grid-spaced">
    <div class="status-row">
      <span class="status-key">ゲストユーザー</span>
      <span class="status-val"><?= $guestName ?></span>
    </div>
  </div>

  <?php if ($success): ?>
    <p class="reset-notice reset-guest-notice">パスワードを変更しました。既存のセッションは無効化されました。</p>
    <a class="btn btn-block" href="admin.php">管理ページへ戻る</a>
  <?php else: ?>
    <?php if ($error): ?>
      <div class="reset-error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>
    <form method="POST" action="guest_pwd.php">
      <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
      <input type="hidden" name="id" value="<?= $guestIdH ?>">
      <div class="field">
        <label for="new_password">新しいパスワード</label>
        <div class="pwd-wrap">
          <input type="password" id="new_password" name="new_password"
            autocomplete="new-password" minlength="<?= PWD_MIN_LEN ?>" maxlength="128" placeholder="新しいパスワードを入力" autofocus>
          <button type="button" class="pwd-toggle" aria-label="パスワードを表示" data-target="new_password"></button>
        </div>
      </div>
      <button class="btn" type="submit">パスワードを変更する</button>
    </form>
    <a class="btn-ghost btn-block btn-cancel" href="admin.php">キャンセル</a>
  <?php endif; ?>
</div>
<script type="module" src="../scripts/global.js" nonce="<?= $nonce ?>"></script>
</body>
</html>
