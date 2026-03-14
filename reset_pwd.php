<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

define('USERS_FILE',  '/var/www/private/users.json');
define('RESETS_FILE', '/var/www/private/resets.json');

function load_json(string $path): array {
    if (!is_file($path)) return [];
    $fp = @fopen($path, 'r');
    if ($fp === false) return [];
    if (!flock($fp, LOCK_SH)) { fclose($fp); return []; }
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$raw) return [];
    $d = json_decode($raw, true);
    return is_array($d) ? $d : [];
}

function save_json(string $path, array $data): bool {
    $fp = @fopen($path, 'c+');
    if ($fp === false) { error_log('SAVE_FAIL: ' . $path); return false; }
    if (!flock($fp, LOCK_EX)) { fclose($fp); return false; }
    // 既存のトップレベルキー（admin_lastLoginTime等）を保持してdataキーだけ上書き
    $existing = json_decode(stream_get_contents($fp), true);
    $payload  = is_array($existing) ? array_merge($existing, $data) : $data;
    ftruncate($fp, 0);
    rewind($fp);
    $encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    $ok = (fwrite($fp, $encoded) !== false);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$ok) error_log('SAVE_FAIL: ' . $path);
    return $ok;
}

function validate_token(string $token): ?array {
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $token)) {
        return null;
    }
    $resets = load_json(RESETS_FILE);
    foreach ($resets as $r) {
        if (!isset($r['token'], $r['username'], $r['expires_at'])) continue;
        if (!hash_equals($r['token'], $token)) continue;
        if (time() > (int)$r['expires_at']) return null;
        return ['username' => $r['username']];
    }
    return null;
}

function consume_token(string $token): void {
    $resets = load_json(RESETS_FILE);
    $resets = array_values(array_filter($resets, fn($r) => !hash_equals($r['token'] ?? '', $token)));
    save_json(RESETS_FILE, $resets);
}

session_name('AUTHSID');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
session_start();

if (!empty($_SESSION['authenticated'])) {
    header('Location: index.php', true, 302);
    exit;
}

// POSTボディサイズ上限
$contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($contentLength > 4096) {
    http_response_code(413); exit;
}

$rawToken = $_GET['token'] ?? '';
$entry    = validate_token($rawToken);
$token    = htmlspecialchars($rawToken, ENT_QUOTES, 'UTF-8');

$step  = 'verify';
$error = '';

if ($entry === null) {
    $step = 'invalid';

} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfPost = $_POST['csrf_token'] ?? '';
    if (!is_string($csrfPost) || empty($_SESSION['reset_csrf']) ||
        !hash_equals($_SESSION['reset_csrf'], $csrfPost)) {
        $step = 'invalid';
    } else {
        $postStep = $_POST['step'] ?? '';

        if ($postStep === 'verify') {
            $inputName = trim($_POST['username'] ?? '');
            // 定時間応答でタイミング差によるユーザー名列挙を防ぐ
            $startTime = microtime(true);

            if ($inputName === '' || !preg_match('/^[a-zA-Z0-9_\-\.]{1,64}$/', $inputName)) {
                $error = 'ユーザー名を正しく入力してください。';
                $step  = 'verify';
            } elseif (!hash_equals($entry['username'], $inputName)) {
                $error = 'ユーザー名が一致しません。';
                $step  = 'verify';
            } else {
                $_SESSION['reset_verified_user'] = $entry['username'];
                $_SESSION['reset_token']         = $rawToken;
                $step = 'set';
            }

            // 最低150ms保証（タイミング均一化）
            $elapsed = (int)((microtime(true) - $startTime) * 1_000_000);
            $wait    = 150000 - $elapsed;
            if ($wait > 0) usleep($wait);

        } elseif ($postStep === 'set') {
            if (
                empty($_SESSION['reset_verified_user']) ||
                empty($_SESSION['reset_token'])         ||
                !hash_equals($_SESSION['reset_token'], $rawToken)
            ) {
                $step = 'invalid';
            } else {
                $hash     = strtolower(trim($_POST['pwdhash'] ?? ''));
                $username = $_SESSION['reset_verified_user'];

                if (!preg_match('/^[0-9a-f]{128}$/', $hash)) {
                    $error = '不正な送信です。もう一度お試しください。';
                    $step  = 'set';
                } else {
                    $usersData = load_json(USERS_FILE);
                    $users     = $usersData['data'] ?? [];
                    $saved     = false;
                    foreach ($users as &$u) {
                        if (($u['name'] ?? '') === $username) {
                            $u['pwdhash'] = $hash;
                            $saved = true;
                            break;
                        }
                    }
                    unset($u);

                    if (!$saved) {
                        $error = 'ユーザーが見つかりません。管理者に連絡してください。';
                        $step  = 'set';
                    } elseif (!save_json(USERS_FILE, ['data' => array_values($users)])) {
                        $error = '保存に失敗しました。管理者に連絡してください。';
                        $step  = 'set';
                    } else {
                        consume_token($rawToken);
                        error_log('PWD_RESET_DONE user=' . $username);

                        session_unset();
                        session_destroy();

                        header('Location: login.php?reset=done', true, 302);
                        exit;
                    }
                }
            }
        } else {
            $step = 'invalid';
        }
    }
} else {
    unset($_SESSION['reset_verified_user'], $_SESSION['reset_token']);
    $step = 'verify';
}

if ($step !== 'invalid' && empty($_SESSION['reset_csrf'])) {
    $_SESSION['reset_csrf'] = bin2hex(random_bytes(32));
}

require_once __DIR__ . '/nonce_helper.php';
$nonce = generate_nonce();
emit_csp($nonce, "'self' https://project.activetk.jp");

$csrf         = htmlspecialchars($_SESSION['reset_csrf'] ?? '', ENT_QUOTES, 'UTF-8');
$errorHtml    = $error ? htmlspecialchars($error, ENT_QUOTES, 'UTF-8') : '';
$verifiedUser = htmlspecialchars(
    $_SESSION['reset_verified_user'] ?? ($entry['username'] ?? ''),
    ENT_QUOTES, 'UTF-8'
);
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, max-image-preview:none, max-video-preview:0, noimageindex, unavailable-after:Thu, 24 Nov 2022 00:00:00 +0900">
<title>パスワードリセット</title>
<link rel="stylesheet" href="styles/global.css" nonce="<?= $nonce ?>">
<script src="https://code.activetk.jp/archive-today.blocker.js" nonce="<?= $nonce ?>" defer></script>
<script nonce="<?= $nonce ?>">var _0x1e85d5=_0xac99;window.cp='cmswZXhuLnRhdHN1dC5qcA==',window.cpe='JUUzJTgxJTkzJUUzJTgxJUFFJUUzJTgyJUI1JUUzJTgyJUE0JUUzJTgzJTg4JUUzJTgxJUFGJUU2JTlDJUFDJUU2JTlEJUE1JUUzJTgxJUFFJUU2JTgzJUIzJUU1JUFFJTlBJUUzJTgxJUE4JUUzJTgxJUFGJUU5JTgxJTk1JUUzJTgxJTg2JUUzJTgxJUE3JUU0JUJEJUJGJUU3JTk0JUE4JUUzJTgxJTk1JUUzJTgyJThDJUUzJTgxJUE2JUUzJTgxJTg0JUUzJTgyJThCJUU1JThGJUFGJUU4JTgzJUJEJUU2JTgwJUE3JUUzJTgxJThDJUUzJTgxJTgyJUUzJTgyJThBJUUzJTgxJUJFJUUzJTgxJTk5JUUzJTgwJTgyJTNDYnIlM0UlRTYlOUMlQUMlRTYlOUQlQTUlRTMlODElQUUlRTMlODIlQjUlRTMlODIlQTQlRTMlODMlODglRTMlODElQUUlRTclQUUlQTElRTclOTAlODYlRTglODAlODUlRTMlODElQUIlRTklODAlQTMlRTclQjUlQTElRTMlODElOTclRTMlODElQTYlRTMlODElOEYlRTMlODElQTAlRTMlODElOTUlRTMlODElODQlRTMlODAlODIlM0NiciUzRSVFNiU5QyVBQyVFNiU5RCVBNSVFMyU4MSVBRSVFMyU4MiVCNSVFMyU4MiVBNCVFMyU4MyU4OCVFRiVCQyU5QWh0dHBzJTNBJTJGJTJGcmswZXhuLnRhdHN1dC5qcA==';function _0xac99(_0x3aecaa,_0x2e640e){var _0x40b52b=_0x40b5();return _0xac99=function(_0x15110b,_0x389c09){_0x15110b=_0x15110b-0xdb;var _0x3d0fc0=_0x40b52b[_0x15110b];return _0x3d0fc0;},_0xac99(_0x3aecaa,_0x2e640e);}(function(_0x28fef4,_0x507f58){var _0x4ba24d=_0xac99,_0x51bc4d=_0x28fef4();while(!![]){try{var _0x27b60a=-parseInt(_0x4ba24d(0xdf))/0x1*(parseInt(_0x4ba24d(0xdc))/0x2)+parseInt(_0x4ba24d(0xde))/0x3*(-parseInt(_0x4ba24d(0xe1))/0x4)+parseInt(_0x4ba24d(0xdd))/0x5*(-parseInt(_0x4ba24d(0xe2))/0x6)+parseInt(_0x4ba24d(0xe6))/0x7*(-parseInt(_0x4ba24d(0xe0))/0x8)+-parseInt(_0x4ba24d(0xe8))/0x9*(-parseInt(_0x4ba24d(0xea))/0xa)+-parseInt(_0x4ba24d(0xe4))/0xb*(parseInt(_0x4ba24d(0xe9))/0xc)+parseInt(_0x4ba24d(0xe3))/0xd;if(_0x27b60a===_0x507f58)break;else _0x51bc4d['push'](_0x51bc4d['shift']());}catch(_0x5ebc95){_0x51bc4d['push'](_0x51bc4d['shift']());}}}(_0x40b5,0x60f9d),document[_0x1e85d5(0xe5)](_0x1e85d5(0xdb),function(){var _0x3bc523=_0x1e85d5;decodeURIComponent(btoa(window['location'][_0x3bc523(0xeb)]))!=window['cp']&&document[_0x3bc523(0xe7)](decodeURIComponent(atob(window['cpe'])));}));function _0x40b5(){var _0x4b1445=['92540KSvSPW','host','DOMContentLoaded','6sYMyTb','5UgfKcP','3zOvJRz','169577bwQSBJ','8zOBdPB','2044716LSbUIz','1277808NtISmv','24526827gLoDvd','11KPkjdL','addEventListener','2096507BFeUPV','write','360GzcSBX','3926964FAHSEF'];_0x40b5=function(){return _0x4b1445;};return _0x40b5();}</script>
</head>
<body data-page="reset">
<div class="panel">

<?php if ($step === 'invalid'): ?>
  <div class="panel-label">Password Reset</div>
  <h1><em>「</em>リンク無効<em>」</em></h1>
  <p class="reset-notice">このリセットリンクは無効か、期限切れです。<br>管理者に再発行を依頼してください。</p>
  <a class="btn btn-block" href="login.php">ログインへ戻る</a>

<?php elseif ($step === 'verify'): ?>
  <div class="panel-label">Password Reset &mdash; Step 1 / 2</div>
  <h1><em>「</em>本人確認<em>」</em></h1>
  <p class="reset-notice">ユーザー名を入力して本人確認を行います。</p>
  <form method="POST" action="reset_pwd.php?token=<?= $token ?>">
    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
    <input type="hidden" name="step" value="verify">
    <div class="field">
      <label for="uname">ユーザー名</label>
      <input type="text" id="uname" name="username"
        autocomplete="username" spellcheck="false"
        maxlength="64" placeholder="ユーザー名を入力" autofocus>
    </div>
    <?php if ($errorHtml): ?><div class="reset-error"><?= $errorHtml ?></div><?php endif; ?>
    <button class="btn" type="submit">確認する</button>
  </form>

<?php elseif ($step === 'set'): ?>
  <div class="panel-label">Password Reset &mdash; Step 2 / 2</div>
  <h1><em>「</em>新しいパスワード<em>」</em></h1>
  <div class="status-grid status-grid-spaced">
    <div class="status-row">
      <span class="status-key">ユーザー</span>
      <span class="status-val"><?= $verifiedUser ?></span>
    </div>
  </div>
  <form method="POST" action="reset_pwd.php?token=<?= $token ?>" id="setForm">
    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
    <input type="hidden" name="step" value="set">
    <input type="hidden" name="pwdhash" id="pwdhash">
    <div class="field">
      <label for="pwd1">新しいパスワード</label>
      <div class="pwd-wrap">
        <input type="password" id="pwd1" autocomplete="new-password" maxlength="128" placeholder="新しいパスワードを入力" autofocus>
        <button type="button" class="pwd-toggle" aria-label="パスワードを表示" data-target="pwd1"></button>
      </div>
    </div>
    <div class="field">
      <label for="pwd2">確認用パスワード</label>
      <div class="pwd-wrap">
        <input type="password" id="pwd2" autocomplete="new-password" maxlength="128" placeholder="もう一度入力してください">
        <button type="button" class="pwd-toggle" aria-label="パスワードを表示" data-target="pwd2"></button>
      </div>
    </div>
    <?php if ($errorHtml): ?><div class="reset-error"><?= $errorHtml ?></div><?php endif; ?>
    <button class="btn" type="submit" id="setBtn">パスワードを設定する</button>
  </form>
  <div class="progress-bar"><div class="progress-inner" id="prog"></div></div>

<?php endif; ?>
</div>

<?php if ($step === 'set'): ?>
<script type="module" src="scripts/global.js" nonce="<?= $nonce ?>"></script>
<?php endif; ?>
</body>
</html>