<?php
declare(strict_types=1);

// ─── Impersonate / Bot対策フィルタ（フォームPOST向け） ───────────────────────
// フォームサブミットの正規Fetch Metadata:
//   Sec-Fetch-Mode: navigate, Sec-Fetch-Dest: document, Sec-Fetch-Site: same-origin
$_ua     = $_SERVER['HTTP_USER_AGENT']      ?? '';
$_accEnc = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
$_accLng = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
$_secMode = $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '';
$_secSite = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
$_secDest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? '';
$_origin  = $_SERVER['HTTP_ORIGIN']         ?? '';
$_host    = $_SERVER['HTTP_HOST']           ?? '';

if ($_ua === '' || $_accEnc === '' || $_accLng === '') {
    http_response_code(403); exit;
}
if (preg_match('/^(curl|python|go-http|java|ruby|perl|php|axios|got|node-fetch|okhttp|libwww)/i', $_ua)) {
    http_response_code(403); exit;
}
if (stripos($_accEnc, 'gzip') === false) { http_response_code(403); exit; }

if ($_secMode !== '') {
    // フォームPOSTは navigate のみ。それ以外は偽装リクエスト。
    if (!($_secMode === 'navigate' && $_secSite === 'same-origin' && $_secDest === 'document')) {
        http_response_code(403); exit;
    }
}
// Origin が付く場合は同一ホスト検証
if ($_origin !== '' && parse_url($_origin, PHP_URL_HOST) !== $_host) {
    http_response_code(403); exit;
}
unset($_ua, $_accEnc, $_accLng, $_secMode, $_secSite, $_secDest, $_origin, $_host);

session_name('AUTHSID');
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>true,'httponly'=>true,'samesite'=>'Strict']);
session_start();

// ─── 認証ガード ───────────────────────────────────────────────────────────────
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

// UAフィンガープリントによるセッションハイジャック検出
function ua_fingerprint_admin(): string {
    return hash('sha256',
        ($_SERVER['HTTP_USER_AGENT']      ?? '') .
        ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '') .
        ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '')
    );
}
if (isset($_SESSION['_ua']) && !hash_equals($_SESSION['_ua'], ua_fingerprint_admin())) {
    error_log('ADMIN_SESSION_HIJACK_SUSPECTED ip=' . ($_SERVER['REMOTE_ADDR'] ?? ''));
    session_unset(); session_destroy();
    header('Location: ../login.php', true, 302); exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: admin.php', true, 302); exit;
}

// リクエストボディサイズ上限（巨大POSTによるDoS防止）
$contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($contentLength > 8192) {
    http_response_code(413);
    exit('REQUEST_TOO_LARGE');
}

define('USERS_FILE',  '/var/www/private/users.json');
define('RESETS_FILE', '/var/www/private/resets.json');

require_once __DIR__ . '/../guest_helper.php';

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

function save_users(array $users): bool {
    $fp = @fopen(USERS_FILE, 'c+');
    if ($fp === false) { error_log('SAVE_USERS_OPEN_FAIL: ' . USERS_FILE); return false; }
    if (!flock($fp, LOCK_EX)) { fclose($fp); return false; }
    $existing = json_decode(stream_get_contents($fp), true);
    $payload  = is_array($existing) ? $existing : [];
    $payload['data'] = array_values($users);
    ftruncate($fp, 0);
    rewind($fp);
    $encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    $ok = (fwrite($fp, $encoded) !== false);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$ok) error_log('SAVE_USERS_WRITE_FAIL: ' . USERS_FILE);
    return $ok;
}

function load_resets(): array {
    if (!is_file(RESETS_FILE)) return [];
    $fp = @fopen(RESETS_FILE, 'r');
    if ($fp === false) return [];
    if (!flock($fp, LOCK_SH)) { fclose($fp); return []; }
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$raw) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function save_resets(array $resets): bool {
    $fp = @fopen(RESETS_FILE, 'c');
    if ($fp === false) { error_log('RESETS_OPEN_FAIL: ' . RESETS_FILE); return false; }
    if (!flock($fp, LOCK_EX)) { fclose($fp); return false; }
    ftruncate($fp, 0);
    rewind($fp);
    $encoded = json_encode($resets, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    $ok = (fwrite($fp, $encoded) !== false);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$ok) error_log('RESETS_WRITE_FAIL: ' . RESETS_FILE);
    return $ok;
}

function new_guid(): string {
    $d = random_bytes(16);
    $d[6] = chr(ord($d[6]) & 0x0f | 0x40);
    $d[8] = chr(ord($d[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($d), 4));
}

// ─── CSRF検証 ─────────────────────────────────────────────────────────────────
$tok = $_POST['csrf_token'] ?? '';
if (!is_string($tok) || !isset($_SESSION['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $tok)) {
    http_response_code(403); exit('CSRF_ERROR');
}

// ─── アクション ───────────────────────────────────────────────────────────────
$action = $_POST['action'] ?? '';

if ($action === 'add') {
    $name = trim($_POST['name'] ?? '');
    $hash = strtolower(trim($_POST['pwdhash'] ?? ''));
    if (!preg_match('/^[a-zA-Z0-9_\-\.]{1,24}$/', $name)) {
        header('Location: admin.php?msg=err_username', true, 302); exit;
    }
    $BANNED_NAMES = ['rk0exn_debug'];
    if (in_array(strtolower($name), array_map('strtolower', $BANNED_NAMES), true)) {
        header('Location: admin.php?msg=err_exists', true, 302); exit;
    }
    if (str_starts_with(strtolower($name), 'guest_')) {
        header('Location: admin.php?msg=err_username', true, 302); exit;
    }
    if (!preg_match('/^[0-9a-f]{128}$/', $hash)) {
        header('Location: admin.php?msg=err_hash', true, 302); exit;
    }
    $users = load_users();
    // ユーザー数上限（無制限追加によるDoS防止）
    if (count($users) >= 30) {
        header('Location: admin.php?msg=err_write', true, 302); exit;
    }
    foreach ($users as $u) {
        if (($u['name'] ?? '') === $name) {
            header('Location: admin.php?msg=err_exists', true, 302); exit;
        }
    }
    $users[] = ['id' => new_guid(), 'name' => $name, 'pwdhash' => $hash];
    if (!save_users($users)) {
        header('Location: admin.php?msg=err_write', true, 302); exit;
    }
    error_log(sprintf('ADMIN_ADD_USER admin=%s new_user=%s', $_SESSION['username'] ?? '', $name));
    header('Location: admin.php?msg=ok_added&added_name=' . urlencode($name), true, 302); exit;

} elseif ($action === 'delete') {
    $id          = $_POST['id'] ?? '';
    // IDをUUID形式に限定
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $id)) {
        header('Location: admin.php?msg=err_notfound', true, 302); exit;
    }
    $users       = load_users();
    $before      = count($users);
    $deletedName = '';
    foreach ($users as $u) {
        if (($u['id'] ?? '') === $id) { $deletedName = $u['name'] ?? ''; break; }
    }
    $users = array_filter($users, fn($u) => ($u['id'] ?? '') !== $id);
    if (count($users) < $before) {
        if (!save_users($users)) {
            header('Location: admin.php?msg=err_write', true, 302); exit;
        }
        // リセット中のエントリも合わせて削除（削除後もリセットURLが有効になる問題を防止）
        $resets = load_resets();
        $resets = array_values(array_filter($resets, fn($r) => ($r['username'] ?? '') !== $deletedName));
        save_resets($resets);
        error_log(sprintf('ADMIN_DELETE_USER admin=%s deleted=%s', $_SESSION['username'] ?? '', $deletedName));
        header('Location: admin.php?msg=ok_deleted&deleted_name=' . urlencode($deletedName), true, 302); exit;
    }
    header('Location: admin.php?msg=err_notfound', true, 302); exit;

} elseif ($action === 'reset_pwd') {
    $id = $_POST['id'] ?? '';
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $id)) {
        header('Location: admin.php?msg=err_notfound', true, 302); exit;
    }
    $users      = load_users();
    $targetName = null;

    foreach ($users as $i => $u) {
        if (($u['id'] ?? '') === $id) {
            $targetName        = $u['name'];
            $users[$i]['pwdhash'] = '';
            break;
        }
    }

    if ($targetName === null) {
        header('Location: admin.php?msg=err_notfound', true, 302); exit;
    }
    if (!save_users($users)) {
        header('Location: admin.php?msg=err_write', true, 302); exit;
    }

    $resets = load_resets();
    $resets = array_values(array_filter($resets, fn($r) => ($r['username'] ?? '') !== $targetName));

    $token    = new_guid();
    $resets[] = [
        'token'      => $token,
        'username'   => $targetName,
        'expires_at' => time() + 300,
    ];
    if (!save_resets($resets)) {
        header('Location: admin.php?msg=err_write', true, 302); exit;
    }

    error_log(sprintf('ADMIN_RESET_PWD admin=%s target=%s', $_SESSION['username'] ?? '', $targetName));
    header('Location: admin.php?msg=ok_reset&token=' . urlencode($token) . '&reset_name=' . urlencode($targetName), true, 302); exit;

} elseif ($action === 'add_guest') {
    $displayName = trim($_POST['display_name'] ?? '');
    $password    = $_POST['password'] ?? '';

    if (!preg_match('/^[a-zA-Z0-9_\-\.]{1,18}$/', $displayName)) {
        header('Location: admin.php?msg=err_guest_name', true, 302); exit;
    }
    if (strlen($password) < PWD_MIN_LEN || strlen($password) > 128) {
        header('Location: admin.php?msg=err_guest_pwd', true, 302); exit;
    }

    $fullName = 'guest_' . $displayName;
    $guests   = load_guests();

    if (count($guests) >= GUEST_MAX) {
        header('Location: admin.php?msg=err_guest_max', true, 302); exit;
    }
    foreach ($guests as $g) {
        if (($g['name'] ?? '') === $fullName) {
            header('Location: admin.php?msg=err_guest_exists', true, 302); exit;
        }
    }

    $d  = random_bytes(16);
    $d[6] = chr(ord($d[6]) & 0x0f | 0x40);
    $d[8] = chr(ord($d[8]) & 0x3f | 0x80);
    $newId = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($d), 4));

    $guests[] = [
        'id'            => $newId,
        'name'          => $fullName,
        'enc_pwd'       => guest_encrypt($password),
        'session_token' => null,
    ];
    if (!save_guests($guests)) {
        header('Location: admin.php?msg=err_write', true, 302); exit;
    }
    error_log(sprintf('ADMIN_ADD_GUEST admin=%s guest=%s', $_SESSION['username'] ?? '', $fullName));
    header('Location: admin.php?msg=ok_guest_added&added_name=' . urlencode($fullName), true, 302); exit;

} elseif ($action === 'delete_guest') {
    $id = $_POST['id'] ?? '';
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $id)) {
        header('Location: admin.php?msg=err_notfound', true, 302); exit;
    }
    $guests      = load_guests();
    $before      = count($guests);
    $deletedName = '';
    foreach ($guests as $g) {
        if (($g['id'] ?? '') === $id) { $deletedName = $g['name'] ?? ''; break; }
    }
    $guests = array_filter($guests, fn($g) => ($g['id'] ?? '') !== $id);
    if (count($guests) < $before) {
        if (!save_guests($guests)) {
            header('Location: admin.php?msg=err_write', true, 302); exit;
        }
        error_log(sprintf('ADMIN_DELETE_GUEST admin=%s deleted=%s', $_SESSION['username'] ?? '', $deletedName));
        header('Location: admin.php?msg=ok_guest_deleted&deleted_name=' . urlencode($deletedName), true, 302); exit;
    }
    header('Location: admin.php?msg=err_notfound', true, 302); exit;

} elseif ($action === 'logout') {
    session_unset();
    session_destroy();
    header('Location: ../login.php', true, 302); exit;

} else {
    header('Location: admin.php', true, 302); exit;
}
