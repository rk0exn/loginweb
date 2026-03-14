<?php
declare(strict_types=1);
require_once __DIR__ . '/nonce_helper.php';

$nonce = generate_nonce();
emit_csp($nonce, "'self' https://project.activetk.jp");
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, max-image-preview:none, max-video-preview:0, noimageindex, unavailable-after:Thu, 24 Nov 2022 00:00:00 +0900">
<title>ログイン</title>
<link rel="stylesheet" href="styles/global.css" nonce="<?= $nonce ?>">
</head>
<body data-page="login">
<div class="panel">
  <div class="panel-label">セキュアアクセス</div>
  <h1><em>「</em>ログイン<em>」</em></h1>

  <div class="field">
    <label for="uname">ユーザー名</label>
    <input type="text" id="uname" name="username"
      autocomplete="username" spellcheck="false"
      maxlength="64" placeholder="ユーザー名を入力">
  </div>
  <div class="field">
    <label for="pwd">パスワード</label>
    <div class="pwd-wrap">
      <input type="password" id="pwd" name="password"
        autocomplete="current-password" maxlength="128" placeholder="パスワードを入力">
      <button type="button" class="pwd-toggle" aria-label="パスワードを表示" data-target="pwd"></button>
    </div>
  </div>

  <button class="btn" id="loginBtn" type="button">ログイン</button>
  <div id="msg" role="alert" aria-live="polite"></div>
  <div class="progress-bar"><div class="progress-inner" id="prog"></div></div>
</div>

<script type="module" src="scripts/global.js" nonce="<?= $nonce ?>"></script>
</body>
</html>
