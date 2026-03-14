<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// ─── Impersonate / Bot対策フィルタ ───────────────────────────────────────────
$ua     = $_SERVER['HTTP_USER_AGENT']      ?? '';
$accept = $_SERVER['HTTP_ACCEPT']          ?? '';
$accEnc = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
$accLng = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';

if ($ua === '' || $accept === '' || $accEnc === '' || $accLng === '') {
    http_response_code(403); exit;
}
if (preg_match('/^(curl|python|go-http|java|ruby|perl|php|axios|got|node-fetch|okhttp|libwww)/i', $ua)) {
    http_response_code(403); exit;
}
if (stripos($accEnc, 'gzip') === false) { http_response_code(403); exit; }

// ─── Long-polling セキュリティガード ─────────────────────────────────────────
// fetch() による same-origin リクエストのみ許可
$origin  = $_SERVER['HTTP_ORIGIN']         ?? '';
$host    = $_SERVER['HTTP_HOST']           ?? '';
$secMode = $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '';
$secSite = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
$secDest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? '';

if ($secMode !== '') {
    if (!($secMode === 'cors' || $secMode === 'same-origin')) { http_response_code(403); exit; }
    if ($secSite !== 'same-origin')                          { http_response_code(403); exit; }
    if ($secDest !== 'empty')                                { http_response_code(403); exit; }
}
if ($origin !== '' && parse_url($origin, PHP_URL_HOST) !== $host) {
    http_response_code(403); exit;
}
if ($secMode === '' && $origin === '') {
    http_response_code(403); exit;
}

// ─── セッション ───────────────────────────────────────────────────────────────
ob_start();
session_name('AUTHSID');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
session_start();

if (empty($_SESSION['authenticated'])) {
    ob_end_clean(); http_response_code(401); exit;
}

$ua = hash('sha256',
    ($_SERVER['HTTP_USER_AGENT']      ?? '') .
    ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '') .
    ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '')
);
if (isset($_SESSION['_ua']) && !hash_equals($_SESSION['_ua'], $ua)) {
    ob_end_clean(); http_response_code(401); exit;
}

$isFallback   = !empty($_SESSION['is_fallback']);
$isGuest      = !empty($_SESSION['is_guest']);
$uid          = $_SESSION['user_id']             ?? '';
$sessHash     = $_SESSION['pwdhash']             ?? '';
$guestId      = $_SESSION['guest_id']            ?? '';
$guestSessTok = $_SESSION['guest_session_token'] ?? '';
$loginAt      = (int)($_SESSION['login_at'] ?? 0);

session_write_close();
ob_end_clean();

// ─── 定数 ─────────────────────────────────────────────────────────────────────
define('USERS_FILE',    '/var/www/private/users.json');
define('POLL_TIMEOUT',  20);   // 最大待機秒数
define('POLL_INTERVAL',  2);   // ポーリング間隔（秒）

require_once __DIR__ . '/guest_helper.php';
$watchFile = $isGuest ? GUESTS_FILE : USERS_FILE;

// ─── レスポンスヘッダー ───────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Cross-Origin-Resource-Policy: same-origin');

// ─── クライアントが最後に見たmtimeを受け取る ─────────────────────────────────
// ?since=<unix_mtime> : この値と現在のmtimeが異なれば即返す
// 未指定 or 0 : 現在のmtimeを返すだけ（初回接続）
$since = (int)($_GET['since'] ?? 0);

// ─── セッション有効期限（一般ユーザーのみ） ──────────────────────────────────
if (!$isFallback && (time() - $loginAt) > 86400) {
    echo json_encode(['event' => 'force_logout', 'reason' => 'session_expired']);
    exit;
}

// ─── 整合性チェック関数 ───────────────────────────────────────────────────────
function check_integrity(string $uid, string $sessHash): string {
    if (!is_file(USERS_FILE)) return 'force_logout';
    $fp = @fopen(USERS_FILE, 'r');
    if ($fp === false) return 'ok';
    if (!flock($fp, LOCK_SH)) { fclose($fp); return 'ok'; }
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$raw) return 'force_logout';
    $json = json_decode($raw, true);
    if (!is_array($json)) return 'force_logout';
    foreach ($json['data'] ?? [] as $u) {
        if (($u['id'] ?? '') !== $uid) continue;
        $stored = $u['pwdhash'] ?? '';
        if ($stored === '') return 'force_logout';
        return hash_equals(strtolower($stored), $sessHash) ? 'ok' : 'force_logout';
    }
    return 'force_logout';
}

// ─── Long-pollingループ ───────────────────────────────────────────────────────
$deadline = time() + POLL_TIMEOUT;

while (true) {
    if (connection_aborted()) exit;

    clearstatcache(true, $watchFile);
    $mtime = @filemtime($watchFile) ?: 0;

    if ($mtime !== $since) {
        if ($isFallback) {
            echo json_encode(['event' => 'admin_reload', 'mtime' => $mtime]);
        } elseif ($isGuest) {
            $ok = check_guest_integrity_by_token($guestId, $guestSessTok);
            echo json_encode($ok
                ? ['event' => 'session_ok',   'mtime' => $mtime]
                : ['event' => 'force_logout', 'reason' => 'session_superseded']
            );
        } else {
            $result = check_integrity($uid, $sessHash);
            echo json_encode($result === 'force_logout'
                ? ['event' => 'force_logout', 'reason' => 'integrity_failed']
                : ['event' => 'session_ok',   'mtime' => $mtime]
            );
        }
        exit;
    }

    if (time() >= $deadline) {
        echo json_encode(['event' => 'noop', 'mtime' => $mtime]);
        exit;
    }

    sleep(POLL_INTERVAL);
}