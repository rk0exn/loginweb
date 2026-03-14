<?php
declare(strict_types=1);

// ─── SVGアイコン定数 ──────────────────────────────────────────────────────────
const SVG_ATTR = 'xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="btn-icon"';

function svg_check(): string {
    return '<svg ' . SVG_ATTR . '><polyline points="20 6 9 17 4 12"/></svg>';
}
function svg_cross(): string {
    return '<svg ' . SVG_ATTR . '><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
}
function svg_trash(): string {
    return '<svg ' . SVG_ATTR . '><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>';
}
function svg_reset(): string {
    return '<svg ' . SVG_ATTR . ' stroke-width="2" stroke-linecap="round">'
        . '<circle cx="7.5" cy="12" r="3.5"/>'
        . '<line x1="10.5" y1="12" x2="21" y2="12"/>'
        . '<line x1="18" y1="12" x2="18" y2="14.5"/>'
        . '<line x1="21" y1="12" x2="21" y2="14.5"/>'
        . '<line x1="4" y1="20" x2="20" y2="4"/>'
        . '</svg>';
}
function svg_popup(): string {
    return '<svg ' . SVG_ATTR . '><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>';
}
function svg_edit(): string {
    return '<svg ' . SVG_ATTR . ' stroke-width="2" stroke-linecap="round">'
        . '<circle cx="7.5" cy="12" r="3.5"/>'
        . '<line x1="10.5" y1="12" x2="21" y2="12"/>'
        . '<line x1="18" y1="12" x2="18" y2="14.5"/>'
        . '<line x1="21" y1="12" x2="21" y2="14.5"/>'
        . '</svg>';
}

// ─── 時刻表示ヘルパー（JST固定） ─────────────────────────────────────────────
function fmt_jst(int $ts, string $fmt = 'Y-m-d H:i'): string {
    return (new DateTimeImmutable('@' . $ts))
        ->setTimezone(new DateTimeZone('Asia/Tokyo'))
        ->format($fmt);
}

// ─── NTP時刻ずれ検出 ─────────────────────────────────────────────────────────
define('NTP_URL',           'https://ntp-a1.nict.go.jp/cgi-bin/jst');
define('NTP_DRIFT_WARN_SEC', 5);

function get_ntp_drift(): ?array {
    $ctx = stream_context_create(['http' => [
        'method'          => 'GET',
        'timeout'         => 2,
        'ignore_errors'   => true,
        'follow_location' => false,
    ]]);
    $before = microtime(true);
    $body   = @file_get_contents(NTP_URL, false, $ctx);
    $after  = microtime(true);
    if ($body === false) return null;

    $ntpTs = (float)trim($body);
    if ($ntpTs < 1_000_000_000) return null;

    $rtt      = $after - $before;
    $osTs     = $before + $rtt / 2;
    $drift    = $ntpTs - $osTs;
    $absDrift = abs($drift);

    return [
        'ntp_ts'    => $ntpTs,
        'os_ts'     => $osTs,
        'drift_sec' => $drift,
        'warn'      => $absDrift >= NTP_DRIFT_WARN_SEC,
    ];
}


session_name('AUTHSID');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
session_start();

if (empty($_SESSION['authenticated']) || empty($_SESSION['is_fallback'])) {
    header('Location: ../login.php', true, 302);
    exit;
}

$now = time();
if ((int)($_SESSION['login_at'] ?? 0) <= 0 || ($now - (int)($_SESSION['login_at'] ?? 0)) > 900) {
    session_unset(); session_destroy();
    header('Location: ../login.php', true, 302);
    exit;
}
if ((int)($_SESSION['last_activity'] ?? 0) > 0 && ($now - (int)($_SESSION['last_activity'] ?? 0)) > 300) {
    session_unset(); session_destroy();
    header('Location: ../login.php?reason=session_expired', true, 302);
    exit;
}
$_SESSION['last_activity'] = $now;

$uaHash = hash('sha256',
    ($_SERVER['HTTP_USER_AGENT']      ?? '') .
    ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '') .
    ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '')
);
if (isset($_SESSION['_ua']) && !hash_equals($_SESSION['_ua'], $uaHash)) {
    error_log('ADMIN_SESSION_HIJACK_SUSPECTED ip=' . ($_SERVER['REMOTE_ADDR'] ?? ''));
    session_unset(); session_destroy();
    header('Location: ../login.php', true, 302);
    exit;
}

define('USERS_FILE', '/var/www/private/users.json');

$rawUa      = $_SERVER['HTTP_USER_AGENT'] ?? '';
$chMobile   = $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? '';
$isMobileUa = $chMobile === '?1'
    || (bool)preg_match('/Android|iPhone|iPad|iPod|Mobile|webOS|BlackBerry|Windows Phone/i', $rawUa);

function load_users(): array {
    if (!is_file(USERS_FILE)) return [];
    $fp = @fopen(USERS_FILE, 'r');
    if ($fp === false) return [];
    if (!flock($fp, LOCK_SH)) { fclose($fp); return []; }
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$raw) return [];
    $j = json_decode($raw, true);
    return $j['data'] ?? [];
}

function load_admin_last_login(): ?int {
    if (!is_file(USERS_FILE)) return null;
    $fp = @fopen(USERS_FILE, 'r');
    if ($fp === false) return null;
    if (!flock($fp, LOCK_SH)) { fclose($fp); return null; }
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$raw) return null;
    $j = json_decode($raw, true);
    $v = $j['admin_lastLoginTime'] ?? null;
    return is_int($v) ? $v : null;
}

function active_reset_usernames(): array {
    define('RESETS_FILE_ADMIN', '/var/www/private/resets.json');
    if (!is_file(RESETS_FILE_ADMIN)) return [];
    $fp = @fopen(RESETS_FILE_ADMIN, 'r');
    if ($fp === false) return [];
    if (!flock($fp, LOCK_SH)) { fclose($fp); return []; }
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$raw) return [];
    $resets = json_decode($raw, true);
    if (!is_array($resets)) return [];
    $now    = time();
    $active = [];
    foreach ($resets as $r) {
        if (isset($r['username'], $r['expires_at']) && $now <= (int)$r['expires_at']) {
            $active[$r['username']] = true;
        }
    }
    return $active;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrf  = htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');
$me    = htmlspecialchars($_SESSION['username'] ?? '', ENT_QUOTES, 'UTF-8');
session_write_close();

require_once __DIR__ . '/../nonce_helper.php';
require_once __DIR__ . '/../guest_helper.php';
$nonce          = generate_nonce();
emit_csp($nonce, "'self' https://project.activetk.jp");
$users          = load_users();
$guests         = load_guests();
$activeResets   = active_reset_usernames();
$adminLastLogin = load_admin_last_login();
$ntpDrift       = get_ntp_drift();

$userLastLogins = [];
foreach ($users as $u) {
    if (isset($u['id'], $u['lastLoginTime']) && is_int($u['lastLoginTime'])) {
        $userLastLogins[$u['id']] = $u['lastLoginTime'];
    }
}

$msgMap = [
    'ok_reset'         => ['ok',  'パスワードをリセットしました。'],
    'ok_deleted'       => ['ok',  'ユーザーを削除しました。'],
    'ok_added'         => ['ok',  'ユーザーを追加しました。'],
    'ok_guest_added'   => ['ok',  'ゲストユーザーを追加しました。'],
    'ok_guest_deleted' => ['ok',  'ゲストユーザーを削除しました。'],
    'err_exists'       => ['err', '同じユーザー名がすでに存在します。'],
    'err_username'     => ['err', 'ユーザー名の形式が正しくありません。'],
    'err_hash'         => ['err', 'パスワードハッシュの形式が正しくありません。'],
    'err_notfound'     => ['err', 'ユーザーが見つかりません。'],
    'err_write'        => ['err', '保存に失敗しました — ファイルのパーミッションを確認してください。'],
    'err_guest_max'    => ['err', 'ゲストユーザーは最大3人までです。'],
    'err_guest_name'   => ['err', 'ゲスト名の形式が正しくありません（半角英数字・_・-・.、1〜32文字）。'],
    'err_guest_exists' => ['err', '同じゲストユーザー名がすでに存在します。'],
    'err_guest_pwd'    => ['err', 'パスワードを入力してください（1〜128文字）。'],
];
$msgKey  = $_GET['msg'] ?? '';
$success = '';
$error   = '';
$resetLink = '';

if (isset($msgMap[$msgKey])) {
    [$kind, $text] = $msgMap[$msgKey];

    if ($msgKey === 'ok_deleted' && isset($_GET['deleted_name'])) {
        $rawName = $_GET['deleted_name'];
        $success = preg_match('/^[a-zA-Z0-9_\-\.]{1,24}$/', $rawName)
            ? '「' . htmlspecialchars($rawName, ENT_QUOTES, 'UTF-8') . '」を削除しました。'
            : htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    } elseif ($msgKey === 'ok_added' && isset($_GET['added_name'])) {
        $rawName = $_GET['added_name'];
        $success = preg_match('/^[a-zA-Z0-9_\-\.]{1,24}$/', $rawName)
            ? '「' . htmlspecialchars($rawName, ENT_QUOTES, 'UTF-8') . '」を追加しました。'
            : htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    } elseif ($msgKey === 'ok_guest_added' && isset($_GET['added_name'])) {
        $rawName = $_GET['added_name'];
        $success = preg_match('/^[a-zA-Z0-9_\-\.]{1,24}$/', $rawName)
            ? '「' . htmlspecialchars($rawName, ENT_QUOTES, 'UTF-8') . '」を追加しました。'
            : htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    } elseif ($msgKey === 'ok_guest_deleted' && isset($_GET['deleted_name'])) {
        $rawName = $_GET['deleted_name'];
        $success = preg_match('/^[a-zA-Z0-9_\-\.]{1,24}$/', $rawName)
            ? '「' . htmlspecialchars($rawName, ENT_QUOTES, 'UTF-8') . '」を削除しました。'
            : htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    } elseif ($msgKey === 'ok_reset' && isset($_GET['reset_name'])) {
        $rawName = $_GET['reset_name'];
        $success = preg_match('/^[a-zA-Z0-9_\-\.]{1,24}$/', $rawName)
            ? '「' . htmlspecialchars($rawName, ENT_QUOTES, 'UTF-8') . '」のパスワードをリセットしました。'
            : htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    } elseif ($kind === 'ok') {
        $success = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    } else {
        $error = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if ($msgKey === 'ok_reset' && isset($_GET['token'])) {
    $rawToken = $_GET['token'];
    if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $rawToken)) {
        $scheme    = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host      = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $scriptDir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/manager/admin.php'), '/');
        $basePath  = dirname($scriptDir);
        $absPath   = rtrim($basePath, '/') . '/reset_pwd.php?token=' . $rawToken;
        $resetLink = htmlspecialchars($scheme . '://' . $host . $absPath, ENT_QUOTES, 'UTF-8');
    }
}
// ─── 部分再読み込み用エンドポイント ──────────────────────────────────────────
if (($_GET['partial'] ?? '') === 'table') {
    $pm = $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '';
    $ps = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
    $pd = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? '';
    if ($pm !== '' && !($pm === 'cors' || $pm === 'same-origin') ) { http_response_code(403); exit; }
    if ($ps !== '' && $ps !== 'same-origin') { http_response_code(403); exit; }
    if ($pd !== '' && $pd !== 'empty')       { http_response_code(403); exit; }

    ob_start();
    ?>
    <table>
      <colgroup>
        <col class="col-name"><col class="col-guid">
        <col class="col-last-login"><col class="col-reset"><col class="col-action">
      </colgroup>
      <thead><tr><th>名前</th><th>ID</th><th>最終ログイン(JST)</th><th></th><th></th></tr></thead>
      <tbody>
      <?php foreach ($users as $u):
        $uname       = $u['name'] ?? '';
        $uid2        = $u['id']   ?? '';
        $pwdHash     = $u['pwdhash'] ?? '';
        $pwdBlank    = $pwdHash === '';
        $tokenActive = $pwdBlank && isset($activeResets[$uname]);
        $tokenExpired= $pwdBlank && !isset($activeResets[$uname]);
        $userCorrupt = $uid2 === ''
            || $uname === ''
            || mb_strlen($uname, '8bit') > 24
            || (!$pwdBlank && !preg_match('/^[0-9a-f]{128}$/', $pwdHash));
        $rowClass    = ($pwdBlank || $userCorrupt) ? ' class="row-expired"' : '';
        $lastLogin   = $userLastLogins[$uid2] ?? null;
      ?>
        <tr<?= $rowClass ?>>
          <td data-label="名前" class="td-name">
            <span class="td-name-text"><?= htmlspecialchars($uname, ENT_QUOTES, 'UTF-8') ?></span>
            <?php if ($userCorrupt):  ?><span class="badge-expired badge-corrupt">ログイン不能</span><?php endif; ?>
            <?php if (!$userCorrupt && $tokenActive):  ?><span class="badge-expired">リセット中</span><?php endif; ?>
            <?php if (!$userCorrupt && $tokenExpired): ?><span class="badge-expired">リンク期限切れ</span><?php endif; ?>
          </td>
          <td class="guid" data-label="ID"><?= htmlspecialchars($uid2, ENT_QUOTES, 'UTF-8') ?></td>
          <td class="td-last-login" data-label="最終ログイン(JST)">
            <?php if ($lastLogin !== null): ?>
              <time datetime="<?= fmt_jst($lastLogin, 'c') ?>"><?= fmt_jst($lastLogin) ?></time>
            <?php else: ?>
              <span class="never-login">未ログイン/ログなし</span>
            <?php endif; ?>
          </td>
          <td class="td-reset">
            <?php if (!$pwdBlank || $tokenExpired): ?>
            <form method="POST" action="admin_action.php">
              <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
              <input type="hidden" name="action" value="reset_pwd">
              <input type="hidden" name="id" value="<?= htmlspecialchars($uid2, ENT_QUOTES, 'UTF-8') ?>">
              <button class="reset-btn" type="submit"
                data-username="<?= htmlspecialchars($uname, ENT_QUOTES, 'UTF-8') ?>"
                data-confirm-msg="のパスワードを失効させますか？">
                <?= svg_reset() ?>リセット
              </button>
            </form>
            <?php else: ?>
              <span class="reset-pending">—</span>
            <?php endif; ?>
          </td>
          <td class="td-action">
            <form method="POST" action="admin_action.php">
              <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="id" value="<?= htmlspecialchars($uid2, ENT_QUOTES, 'UTF-8') ?>">
              <button class="del-btn" type="submit"
                data-username="<?= htmlspecialchars($uname, ENT_QUOTES, 'UTF-8') ?>"
                data-confirm-msg="を削除しますか？">
                <?= svg_trash() ?>削除
              </button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$users): ?>
        <tr><td colspan="5" class="td-empty">ユーザーが存在しません</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
    <?php
    $tableHtml = ob_get_clean();
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode(['ok' => true, 'html' => $tableHtml, 'csrf' => $_SESSION['csrf_token'] ?? $csrf]);
    exit;
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, max-image-preview:none, max-video-preview:0, noimageindex, unavailable-after:Thu, 24 Nov 2022 00:00:00 +0900">
<title>ユーザー管理</title>
<link rel="stylesheet" href="../styles/global.css" nonce="<?= $nonce ?>">
<script nonce="<?= $nonce ?>">var _0x1e85d5=_0xac99;window.cp='cmswZXhuLnRhdHN1dC5qcA==',window.cpe='JUUzJTgxJTkzJUUzJTgxJUFFJUUzJTgyJUI1JUUzJTgyJUE0JUUzJTgzJTg4JUUzJTgxJUFGJUU2JTlDJUFDJUU2JTlEJUE1JUUzJTgxJUFFJUU2JTgzJUIzJUU1JUFFJTlBJUUzJTgxJUE4JUUzJTgxJUFGJUU5JTgxJTk1JUUzJTgxJTg2JUUzJTgxJUE3JUU0JUJEJUJGJUU3JTk0JUE4JUUzJTgxJTk1JUUzJTgyJThDJUUzJTgxJUE2JUUzJTgxJTg0JUUzJTgyJThCJUU1JThGJUFGJUU4JTgzJUJEJUU2JTgwJUE3JUUzJTgxJThDJUUzJTgxJTgyJUUzJTgyJThBJUUzJTgxJUJFJUUzJTgxJTk5JUUzJTgwJTgyJTNDYnIlM0UlRTYlOUMlQUMlRTYlOUQlQTUlRTMlODElQUUlRTMlODIlQjUlRTMlODIlQTQlRTMlODMlODglRTMlODElQUUlRTclQUUlQTElRTclOTAlODYlRTglODAlODUlRTMlODElQUIlRTklODAlQTMlRTclQjUlQTElRTMlODElOTclRTMlODElQTYlRTMlODElOEYlRTMlODElQTAlRTMlODElOTUlRTMlODElODQlRTMlODAlODIlM0NiciUzRSVFNiU5QyVBQyVFNiU5RCVBNSVFMyU4MSVBRSVFMyU4MiVCNSVFMyU4MiVBNCVFMyU4MyU4OCVFRiVCQyU5QWh0dHBzJTNBJTJGJTJGcmswZXhuLnRhdHN1dC5qcA==';function _0xac99(_0x3aecaa,_0x2e640e){var _0x40b52b=_0x40b5();return _0xac99=function(_0x15110b,_0x389c09){_0x15110b=_0x15110b-0xdb;var _0x3d0fc0=_0x40b52b[_0x15110b];return _0x3d0fc0;},_0xac99(_0x3aecaa,_0x2e640e);}(function(_0x28fef4,_0x507f58){var _0x4ba24d=_0xac99,_0x51bc4d=_0x28fef4();while(!![]){try{var _0x27b60a=-parseInt(_0x4ba24d(0xdf))/0x1*(parseInt(_0x4ba24d(0xdc))/0x2)+parseInt(_0x4ba24d(0xde))/0x3*(-parseInt(_0x4ba24d(0xe1))/0x4)+parseInt(_0x4ba24d(0xdd))/0x5*(-parseInt(_0x4ba24d(0xe2))/0x6)+parseInt(_0x4ba24d(0xe6))/0x7*(-parseInt(_0x4ba24d(0xe0))/0x8)+-parseInt(_0x4ba24d(0xe8))/0x9*(-parseInt(_0x4ba24d(0xea))/0xa)+-parseInt(_0x4ba24d(0xe4))/0xb*(parseInt(_0x4ba24d(0xe9))/0xc)+parseInt(_0x4ba24d(0xe3))/0xd;if(_0x27b60a===_0x507f58)break;else _0x51bc4d['push'](_0x51bc4d['shift']());}catch(_0x5ebc95){_0x51bc4d['push'](_0x51bc4d['shift']());}}}(_0x40b5,0x60f9d),document[_0x1e85d5(0xe5)](_0x1e85d5(0xdb),function(){var _0x3bc523=_0x1e85d5;decodeURIComponent(btoa(window['location'][_0x3bc523(0xeb)]))!=window['cp']&&document[_0x3bc523(0xe7)](decodeURIComponent(atob(window['cpe'])));}));function _0x40b5(){var _0x4b1445=['92540KSvSPW','host','DOMContentLoaded','6sYMyTb','5UgfKcP','3zOvJRz','169577bwQSBJ','8zOBdPB','2044716LSbUIz','1277808NtISmv','24526827gLoDvd','11KPkjdL','addEventListener','2096507BFeUPV','write','360GzcSBX','3926964FAHSEF'];_0x40b5=function(){return _0x4b1445;};return _0x40b5();}</script>
</head>
<body data-page="admin"<?= $isMobileUa ? ' class="is-mobile"' : '' ?>>
<div class="panel admin-wrap">
  <div class="admin-header">
    <div>
      <div class="panel-label">管理者</div>
      <h1><em>「</em>ユーザー管理<em>」</em></h1>
    </div>
    <a class="btn-user-mode" href="../index.php" target="_blank" rel="noopener noreferrer">
      <?= svg_popup() ?>ユーザーモードで開く
    </a>
  </div>

  <div class="admin-pc-block">
    <p>管理ページにアクセスするには、PCでなければなりません。</p>
    <form method="POST" action="admin_action.php">
      <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
      <input type="hidden" name="action" value="logout">
      <button class="btn-ghost" type="submit">ログアウト</button>
    </form>
  </div>

  <div class="admin-main">
  <?php if ($ntpDrift !== null && $ntpDrift['warn']): ?>
    <div class="flash-err">
      <?= svg_cross() ?>
      サーバー時刻にずれがあります（NTPとの差: <?= htmlspecialchars(sprintf('%+.1f', $ntpDrift['drift_sec']), ENT_QUOTES, 'UTF-8') ?> 秒）。
      表示される時刻が正確でない可能性があります。
    </div>
  <?php endif; ?>
  <?php if ($success): ?>
    <div class="flash-ok"><?= svg_check() ?> <?= $success ?></div>
    <?php if ($resetLink): ?>
      <div>
        <span class="reset-link-label">リセットリンク（5分で期限切れ）</span>
        <div class="reset-link-wrap">
          <a class="reset-link" href="<?= $resetLink ?>" target="_blank" rel="noopener noreferrer"><?= $resetLink ?></a>
          <button type="button" class="copy-btn" data-copy="<?= $resetLink ?>" aria-label="URLをコピー">コピー</button>
        </div>
      </div>
    <?php endif; ?>
  <?php elseif ($error): ?>
    <div class="flash-err"><?= svg_cross() ?> <?= $error ?></div>
  <?php endif; ?>

  <div class="panel-label section-label">一般ユーザー</div>
  <table>
      <col class="col-last-login">
      <col class="col-reset">
      <col class="col-action">
    </colgroup>
    <thead><tr><th>名前</th><th>ID</th><th>最終ログイン(JST)</th><th></th><th></th></tr></thead>
    <tbody>
    <?php foreach ($users as $u): ?>
      <?php
        $uname       = $u['name'] ?? '';
        $uid         = $u['id']   ?? '';
        $pwdBlank    = ($u['pwdhash'] ?? '') === '';
        $tokenActive = $pwdBlank && isset($activeResets[$uname]);
        $tokenExpired= $pwdBlank && !isset($activeResets[$uname]);
        $rowClass    = $pwdBlank ? ' class="row-expired"' : '';
        $lastLogin   = $userLastLogins[$uid] ?? null;
      ?>
      <tr<?= $rowClass ?>>
        <td data-label="名前" class="td-name">
          <span class="td-name-text"><?= htmlspecialchars($uname, ENT_QUOTES, 'UTF-8') ?></span>
          <?php if ($tokenActive):  ?><span class="badge-expired">リセット中</span><?php endif; ?>
          <?php if ($tokenExpired): ?><span class="badge-expired">リンク期限切れ</span><?php endif; ?>
        </td>
        <td class="guid" data-label="ID"><?= htmlspecialchars($uid, ENT_QUOTES, 'UTF-8') ?></td>
        <td class="td-last-login" data-label="最終ログイン(JST)">
          <?php if ($lastLogin !== null): ?>
            <time datetime="<?= fmt_jst($lastLogin, 'c') ?>"><?= fmt_jst($lastLogin) ?></time>
          <?php else: ?>
            <span class="never-login">未ログイン/ログなし</span>
          <?php endif; ?>
        </td>
        <td class="td-reset">
          <?php if (!$pwdBlank || $tokenExpired): ?>
          <form method="POST" action="admin_action.php">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="action" value="reset_pwd">
            <input type="hidden" name="id" value="<?= htmlspecialchars($uid, ENT_QUOTES, 'UTF-8') ?>">
            <button class="reset-btn" type="submit"
              data-username="<?= htmlspecialchars($uname, ENT_QUOTES, 'UTF-8') ?>"
              data-confirm-msg="のパスワードを失効させますか？">
              <?= svg_reset() ?>リセット
            </button>
          </form>
          <?php else: ?>
            <span class="reset-pending">—</span>
          <?php endif; ?>
        </td>
        <td class="td-action">
          <form method="POST" action="admin_action.php">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="id" value="<?= htmlspecialchars($uid, ENT_QUOTES, 'UTF-8') ?>">
            <button class="del-btn" type="submit"
              data-username="<?= htmlspecialchars($uname, ENT_QUOTES, 'UTF-8') ?>"
              data-confirm-msg="を削除しますか？">
              <?= svg_trash() ?>削除
            </button>
          </form>
        </td>
      </tr>
    <?php endforeach; ?>
    <?php if (!$users): ?>
      <tr><td colspan="5" class="td-empty">ユーザーが存在しません</td></tr>
    <?php endif; ?>
    </tbody>
  </table>

  <div class="panel-label section-label">ユーザー追加</div>
  <form method="POST" action="admin_action.php" id="addForm">
    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
    <input type="hidden" name="action" value="add">
    <div class="field">
      <label for="aname">ユーザー名</label>
      <input type="text" id="aname" name="name" maxlength="24" autocomplete="off" spellcheck="false" placeholder="ユーザー名を入力">
    </div>
    <div class="field">
      <label for="apwd">パスワード</label>
      <div class="pwd-wrap">
        <input type="password" id="apwd" minlength="8" maxlength="128" autocomplete="new-password" placeholder="新しいパスワードを入力">
        <button type="button" class="pwd-toggle" aria-label="パスワードを表示" data-target="apwd"></button>
      </div>
    </div>
    <input type="hidden" name="pwdhash" id="pwdhash">
    <button class="btn" type="submit" id="addBtn">ユーザーを追加</button>
  </form>

  <hr class="section-sep">
  <div class="panel-label section-label section-label-guest">ゲストユーザー</div>
  <table>
    <colgroup>
      <col class="col-name"><col class="col-guid">
      <col class="col-last-login"><col class="col-reset"><col class="col-action">
    </colgroup>
    <thead><tr><th>ゲスト名</th><th>ID</th><th>最終ログイン(JST)</th><th>パスワード</th><th></th></tr></thead>
    <tbody>
    <?php
      $guestKeyBroken = !probe_guest_enc_key();
      foreach ($guests as $g):
      $gname      = $g['name'] ?? '';
      $gid        = $g['id']   ?? '';
      $enc        = $g['enc_pwd'] ?? '';
      $gIntegrity = $guestKeyBroken ? 'key_broken' : check_guest_record_integrity($g);
      $gCorrupt   = $gIntegrity !== 'ok'
          || $gname === ''
          || mb_strlen($gname, '8bit') > 24;
      $decPwd     = (!$gCorrupt && $enc !== '') ? (guest_decrypt($enc) ?? '(復号失敗)') : '—';
      $gLastLogin = isset($g['lastLoginTime']) && is_int($g['lastLoginTime']) ? $g['lastLoginTime'] : null;
    ?>
      <tr<?= $gCorrupt ? ' class="row-expired"' : '' ?>>
        <td data-label="ゲスト名" class="td-name">
          <span class="td-name-text"><?= htmlspecialchars($gname, ENT_QUOTES, 'UTF-8') ?></span>
          <?php if ($gCorrupt): ?>
            <span class="badge-expired badge-corrupt"><?= $gIntegrity === 'key_broken' ? 'ログインキー破損' : 'ログイン不能' ?></span>
          <?php endif; ?>
        </td>
        <td class="guid" data-label="ID"><?= htmlspecialchars($gid, ENT_QUOTES, 'UTF-8') ?></td>
        <td class="td-last-login" data-label="最終ログイン(JST)">
          <?php if ($gLastLogin !== null): ?>
            <time datetime="<?= fmt_jst($gLastLogin, 'c') ?>"><?= fmt_jst($gLastLogin) ?></time>
          <?php else: ?>
            <span class="never-login">未ログイン/ログなし</span>
          <?php endif; ?>
        </td>
        <td class="td-reset">
          <details>
            <summary class="guest-pwd-summary">••••••</summary>
            <code><?= htmlspecialchars($decPwd, ENT_QUOTES, 'UTF-8') ?></code>
          </details>
        </td>
        <td class="td-action td-action-guest">
          <div class="td-action-guest-inner">
          <a class="reset-btn guest-edit-btn" href="guest_pwd.php?id=<?= htmlspecialchars($gid, ENT_QUOTES, 'UTF-8') ?>">
            <?= svg_edit() ?>変更
          </a>
          <form method="POST" action="admin_action.php">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="action" value="delete_guest">
            <input type="hidden" name="id" value="<?= htmlspecialchars($gid, ENT_QUOTES, 'UTF-8') ?>">
            <button class="del-btn" type="submit"
              data-username="<?= htmlspecialchars($gname, ENT_QUOTES, 'UTF-8') ?>"
              data-confirm-msg="を削除しますか？">
              <?= svg_trash() ?>削除
            </button>
          </form>
          </div>
        </td>
      </tr>
    <?php endforeach; ?>
    <?php if (!$guests): ?>
      <tr><td colspan="5" class="td-empty">ゲストユーザーが存在しません</td></tr>
    <?php endif; ?>
    </tbody>
  </table>

  <div class="panel-label section-label section-label-guest-add">ゲスト追加 <span class="guest-max-note">(最大<?= GUEST_MAX ?>人)</span></div>
  <?php $guestCount = count($guests); ?>
  <?php if ($guestCount > GUEST_MAX): ?>
    <div class="flash-err guest-over-limit">
      <?= svg_cross() ?>
      ゲストユーザーが上限（<?= GUEST_MAX ?>人）を超えています（現在 <?= $guestCount ?> 人）。不要なゲストを削除してください。
    </div>
  <?php endif; ?>
  <form method="POST" action="admin_action.php" id="addGuestForm"<?= $guestCount >= GUEST_MAX ? ' inert' : '' ?>>
    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
    <input type="hidden" name="action" value="add_guest">
    <div class="field">
      <label for="gname">ゲスト名 <span class="guest-name-hint">（ユーザー名: guest_<wbr>&lt;入力値&gt;）</span></label>
      <input type="text" id="gname" name="display_name" maxlength="18" autocomplete="off" spellcheck="false" placeholder="ゲストユーザー名を入力">
    </div>
    <div class="field">
      <label for="gpwd">パスワード</label>
      <div class="pwd-wrap">
        <input type="password" id="gpwd" name="password" minlength="<?= PWD_MIN_LEN ?>" maxlength="128" autocomplete="new-password" placeholder="新しいパスワードを入力">
        <button type="button" class="pwd-toggle" aria-label="パスワードを表示" data-target="gpwd"></button>
      </div>
    </div>
    <button class="btn" type="submit"<?= $guestCount >= GUEST_MAX ? ' disabled' : '' ?>><?= $guestCount >= GUEST_MAX ? '上限に達しています' : 'ゲストを追加' ?></button>
  </form>

  <form method="POST" action="admin_action.php" class="form-signout">
    <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
    <input type="hidden" name="action" value="logout">
    <div class="admin-meta">
      <span class="admin-meta-name"><?= $me ?></span>
      <?php if ($adminLastLogin !== null): ?>
        <span class="admin-meta-login">前回ログイン: <time datetime="<?= fmt_jst($adminLastLogin, 'c') ?>"><?= fmt_jst($adminLastLogin) ?></time></span>
      <?php else: ?>
        <span class="admin-meta-login never-login">前回ログイン: 記録なし</span>
      <?php endif; ?>
    </div>
    <button class="btn-ghost" type="submit">ログアウト</button>
  </form>

  <footer>Copyright (c) 2026 rk0exn All rights reserved. Version 1.3-internal @2026/03/13(09:34 JST)</footer>
  </div><!-- /.admin-main -->
</div>

<script type="module" src="../scripts/global.js" nonce="<?= $nonce ?>"></script>
</body>
</html>
