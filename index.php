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
