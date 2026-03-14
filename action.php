<?php
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// ─── Impersonate / Bot対策フィルタ ───────────────────────────────────────────

function reject(int $code = 403, string $reason = ''): never {
    if ($reason !== '') error_log('REJECT_' . $code . ' reason=' . $reason
        . ' mode='  . ($_SERVER['HTTP_SEC_FETCH_MODE'] ?? '-')
        . ' site='  . ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '-')
        . ' dest='  . ($_SERVER['HTTP_SEC_FETCH_DEST'] ?? '-')
        . ' origin='. ($_SERVER['HTTP_ORIGIN']         ?? '-')
        . ' ct='    . ($_SERVER['CONTENT_TYPE']        ?? '-')
        . ' ua='    . substr($_SERVER['HTTP_USER_AGENT'] ?? '-', 0, 60)
    );
    http_response_code($code); exit;
}

// ① 必須ヘッダーの存在確認
// 正規ブラウザは必ずこれらを送出する。curl_cffi等が忘れやすい。
$ua     = $_SERVER['HTTP_USER_AGENT']      ?? '';
$accept = $_SERVER['HTTP_ACCEPT']          ?? '';
$accEnc = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
$accLng = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';

if ($ua === '' || $accept === '' || $accEnc === '' || $accLng === '') reject(403, 'MISSING_HEADERS');

// ② User-Agent 最低限の整合性（空・既知スキャナ・ライブラリ文字列を拒否）
if (preg_match(
    '/^(curl|python|go-http|java|ruby|perl|php|axios|got|node-fetch|okhttp|libwww)/i',
    $ua
)) reject(403, 'BAD_UA');

// ③ Accept ヘッダーの内容検証
// fetch() / XHR は "application/json, */*" 等を送らず "*/*" や "text/html,..." になる
// ブラウザの fetch は通常 Accept: */* を送出するが、
// Impersonateツールは Accept を省略するか異常値を入れることが多い
if (strlen($accept) > 512) reject(403, 'ACCEPT_TOO_LONG');

// ④ Accept-Encoding に gzip が含まれること（全ブラウザ必須）
if (stripos($accEnc, 'gzip') === false) reject(403, 'NO_GZIP');

// ⑤ Sec-Fetch-* 整合性検証（Fetch Metadata）
// ブラウザは必ず付与する。Impersonateツールは付け忘れるか矛盾した値を入れる。
$secMode = $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '';
$secSite = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
$secDest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? '';

$method  = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$isPost  = ($method === 'POST');
$isGet   = ($method === 'GET');

// GET系エンドポイント（challenge, check, logout, change_pwd_challenge）:
//   same-origin ページからの fetch → mode=same-origin, site=same-origin, dest=empty
// POST系エンドポイント（login, change_pwd）:
//   同上
// Fetch Metadata なしは古いブラウザのみ許容（UAで判定済みのため通過させる）
if ($secMode !== '') {
    // navigate（通常のページ遷移）は action.php への直接アクセスなので拒否
    // no-cors は攻撃者が fetch で任意に設定できるため拒否
    // cors / same-origin はどちらも正規の fetch() から来うる値なので両方許可
    if (!in_array($secMode, ['cors', 'same-origin'], true)) reject(403, 'SEC_MODE');
    // site は same-origin のみ許可（クロスオリジンfetchを遮断する主要ガード）
    if ($secSite !== 'same-origin') reject(403, 'SEC_SITE');
    // dest は empty のみ許可（fetch/XHR以外 = script/img等の埋め込みを拒否）
    if ($secDest !== 'empty') reject(403, 'SEC_DEST');
}

// ⑥ Origin ヘッダー検証（POST時は必須）
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$host   = $_SERVER['HTTP_HOST']   ?? '';
if ($isPost) {
    // POSTに Origin がない = CSRF防止機構を持たない古いクライアント or bot
    if ($origin === '') reject(403, 'NO_ORIGIN_POST');
}
if ($origin !== '' && parse_url($origin, PHP_URL_HOST) !== $host) reject(403, 'ORIGIN_MISMATCH');

// ⑦ Content-Type 検証（POST時）
$ct = $_SERVER['CONTENT_TYPE'] ?? '';
if ($isPost && strpos($ct, 'application/x-www-form-urlencoded') === false) reject(403, 'BAD_CT');

// ⑧ リクエストサイズ上限（巨大POSTによるDoS防止）
if ($isPost) {
    $cl = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($cl > 16384) reject(413);
}

// ⑨ エンドポイント判定（正規パスのみ処理）
$isApi = (
    isset($_GET['check']) || isset($_GET['logout']) || isset($_GET['challenge'])
    || isset($_GET['change_pwd']) || isset($_GET['change_pwd_challenge'])
    || isset($_GET['pow_challenge']) || isset($_GET['pow_verify'])
    || $isPost
);
if (!$isApi) { http_response_code(204); exit; }

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
header('Cross-Origin-Resource-Policy: same-origin');

// ─── 定数 ─────────────────────────────────────────────────────────────────────
define('USERS_FILE',       '/var/www/private/users.json');
define('SESSION_NAME',     'AUTHSID');
define('RATE_WINDOW',      60);
define('IP_RATE_LIMIT',    15);             // IP単位: 60秒あたり最大リクエスト数
define('GLOBAL_RATE_LIMIT', 300);           // 全IP合算: 60秒あたり上限（DDoS緩和）
define('LOCK_FILE_DIR',    '/var/www/private/rate/');
define('GLOBAL_LOCK_FILE', '/var/www/private/rate/_global.json');
define('CHALLENGE_TTL',    120);            // nonce有効期限（秒）- 短縮
define('MAX_FAILS',        3);              // ロックまでの失敗許容数 - 厳格化
define('LOCK_DURATION_BASE', 30);           // 初回ロック秒数（指数バックオフの基数）
define('LOCK_MAX_DURATION',  3600);         // ロック上限（1時間）
define('POW_BASE_DIFFICULTY', 12);   // 低負荷時の初期difficulty（2^12≈4096試行）
define('POW_MAX_DIFFICULTY',  20);   // 高負荷時の上限difficulty（2^20≈100万試行 = 初期の256倍）
define('POW_TARGET_COUNT',   300);   // この1時間アクセス数で最大難易度に到達
define('POW_SCALE',           10);   // 立ち上がり滑らかさ調整（大きいほど緩やか）
define('POW_HOUR_FILE',    '/var/www/private/rate/_pow_hour.json'); // 1時間ウィンドウカウンタ
define('POW_TTL',          300);
define('POW_TOKEN_TTL',    600);

// フォールバック管理者認証はデフォルト無効。
// 運用上必要な場合のみ環境変数で明示的に有効化する。
define('FB_USER',    (string)getenv('LOGINWEB_FALLBACK_USER'));
define('FB_HASH',    strtolower((string)getenv('LOGINWEB_FALLBACK_HASH_SHA512')));
define('FB_WM_KEY',  (string)getenv('LOGINWEB_FALLBACK_WEBMASTER_KEY'));
define('FB_USER_ID', (string)getenv('LOGINWEB_FALLBACK_USER_ID'));

require_once __DIR__ . '/guest_helper.php';

// ─── ユーティリティ ───────────────────────────────────────────────────────────
function json_abort(int $code, string $error): never {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $error]);
    exit;
}

function get_client_ip(): string {
    // プロキシヘッダーは信頼しない（Webサーバー側でX-Real-IPを設定する構成なら別途調整）
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function ua_fingerprint(): string {
    return hash('sha256',
        ($_SERVER['HTTP_USER_AGENT']        ?? '') .
        ($_SERVER['HTTP_ACCEPT_LANGUAGE']   ?? '') .
        ($_SERVER['HTTP_ACCEPT_ENCODING']   ?? '')
    );
}

// ─── セッション ───────────────────────────────────────────────────────────────
function session_params(): void {
    session_name(SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function start_session_stable(): void {
    session_params();
    session_start();
}

function init_session(): void {
    session_params();
    session_start();
    // PHP8.5: session_regenerate_id はセッションがACTIVEでないとValueErrorを投げる
    // 未認証（ログインフロー途中）でのみ再生成する
    if (empty($_SESSION['authenticated']) && session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
}

// ─── CSRF ─────────────────────────────────────────────────────────────────────
function validate_csrf(): void {
    if (empty($_SESSION['csrf_token'])) {
        $tok = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $tok;
        setcookie('csrf_token', $tok, [
            'path'     => '/',
            'secure'   => true,
            'httponly' => false,
            'samesite' => 'Strict',
        ]);
        json_abort(403, 'CSRF_TOKEN_MISSING');
    }
    $provided = $_POST['csrf_token'] ?? '';
    if (!is_string($provided) || !hash_equals($_SESSION['csrf_token'], $provided)) {
        json_abort(403, 'CSRF_MISMATCH');
    }
}

// ─── レートリミット ───────────────────────────────────────────────────────────
function atomic_rate_file(string $path, int $limit): void {
    $dir = dirname($path);
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        // ディレクトリ作成失敗はサービス停止に繋がるため503を返す
        http_response_code(503);
        echo json_encode(['ok' => false, 'error' => 'SERVICE_UNAVAILABLE']);
        exit;
    }
    $fp = @fopen($path, 'c+');
    if ($fp === false) {
        // ファイルが開けない場合もフェイルクローズド（拒否）
        json_abort(503, 'SERVICE_UNAVAILABLE');
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        json_abort(503, 'SERVICE_UNAVAILABLE');
    }
    $now  = time();
    $raw  = stream_get_contents($fp);
    $data = ['count' => 0, 'since' => $now];
    if ($raw) {
        $tmp = json_decode($raw, true);
        if (is_array($tmp) && ($now - (int)($tmp['since'] ?? 0)) < RATE_WINDOW) {
            $data = $tmp;
        }
    }
    $data['count']++;
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    if ($data['count'] > $limit) {
        json_abort(429, 'RATE_LIMIT_EXCEEDED');
    }
}

function check_rate_limit(): void {
    // グローバルカウンタ（全IP合算）: DDoS緩和
    atomic_rate_file(GLOBAL_LOCK_FILE, GLOBAL_RATE_LIMIT);

    // IP単位カウンタ
    $ip   = get_client_ip();
    $safe = preg_replace('/[^a-fA-F0-9:.]/', '_', $ip);
    atomic_rate_file(LOCK_FILE_DIR . $safe . '.json', IP_RATE_LIMIT);
}

// ─── セッションロックアウト（指数バックオフ） ────────────────────────────────
function check_server_lockout(): void {
    $lockUntil = (int)($_SESSION['lock_until'] ?? 0);
    $now       = time();
    if ($lockUntil > $now) {
        json_abort(429, 'LOCKED:' . ($lockUntil - $now));
    }
    if ($lockUntil > 0 && $lockUntil <= $now) {
        // ロック解除後も fail_count は保持（バックオフ計算に使う）
        $_SESSION['lock_until'] = 0;
    }
}

function record_fail(): void {
    $count = (int)($_SESSION['fail_count'] ?? 0) + 1;
    $_SESSION['fail_count'] = $count;
    if ($count >= MAX_FAILS) {
        // 指数バックオフ: base * 2^(超過回数-1)、上限 LOCK_MAX_DURATION
        $exp      = $count - MAX_FAILS;
        $duration = min((int)(LOCK_DURATION_BASE * (2 ** $exp)), LOCK_MAX_DURATION);
        $_SESSION['lock_until'] = time() + $duration;
        error_log(sprintf('AUTH_LOCKOUT ip=%s fails=%d duration=%d', get_client_ip(), $count, $duration));
    }
}

function clear_fails(): void {
    $_SESSION['fail_count'] = 0;
    $_SESSION['lock_until'] = 0;
}

// ─── セッションハイジャック検出 ───────────────────────────────────────────────
function bind_session(): void {
    $ua = ua_fingerprint();
    $ip = get_client_ip();
    if (!isset($_SESSION['_ua'])) {
        $_SESSION['_ua'] = $ua;
        $_SESSION['_ip'] = $ip;
        return;
    }
    // UA変化はハイジャック疑い → セッション破棄
    if (!hash_equals($_SESSION['_ua'], $ua)) {
        error_log('SESSION_HIJACK_SUSPECTED ip=' . $ip);
        session_unset();
        session_destroy();
        json_abort(401, 'SESSION_INVALIDATED');
    }
}

// ─── チャレンジ署名フロー ────────────────────────────────────────────────────
function verify_signed_payload(string $username): array {
    $issuedAt = (int)($_SESSION['challenge_issued_at'] ?? 0);
    if ($issuedAt === 0 || (time() - $issuedAt) > CHALLENGE_TTL) {
        json_abort(400, 'CHALLENGE_EXPIRED');
    }

    $nonce        = $_SESSION['challenge_nonce'] ?? '';
    $clientPubB64 = $_POST['client_pubkey']      ?? '';
    $signatureB64 = $_POST['signature']          ?? '';
    $postedNonce  = $_POST['nonce']              ?? '';
    $pwdhash      = strtolower(trim($_POST['pwdhash'] ?? ''));

    if ($nonce === '' || $clientPubB64 === '' || $signatureB64 === '') {
        json_abort(400, 'MISSING_CRYPTO_FIELDS');
    }
    if (!is_string($postedNonce) || !hash_equals($nonce, $postedNonce)) {
        json_abort(400, 'NONCE_MISMATCH');
    }
    if (!preg_match('/^[0-9a-f]{128}$/', $pwdhash)) {
        json_abort(400, 'INVALID_HASH_FORMAT');
    }

    // Base64デコード前にサイズ上限チェック（巨大データによるDoS防止）
    if (strlen($clientPubB64) > 1024 || strlen($signatureB64) > 1024) {
        json_abort(400, 'PAYLOAD_TOO_LARGE');
    }

    $spkiDer = base64_decode($clientPubB64, true);
    if ($spkiDer === false) json_abort(400, 'INVALID_CLIENT_PUBKEY_ENCODING');

    $pubKeyPem = "-----BEGIN PUBLIC KEY-----\n"
        . chunk_split(base64_encode($spkiDer), 64, "\n")
        . "-----END PUBLIC KEY-----\n";

    $pubKey = openssl_pkey_get_public($pubKeyPem);
    if ($pubKey === false) json_abort(400, 'INVALID_CLIENT_PUBKEY');

    $details = openssl_pkey_get_details($pubKey);
    if (($details['type'] ?? -1) !== OPENSSL_KEYTYPE_RSA) json_abort(400, 'WRONG_KEY_TYPE');
    if (($details['bits'] ?? 0) < 2048)                   json_abort(400, 'RSA_KEY_TOO_SHORT');

    $payload   = $nonce . ':' . $pwdhash;
    $signature = base64_decode($signatureB64, true);
    if ($signature === false) json_abort(400, 'INVALID_SIGNATURE_ENCODING');

    $result = openssl_verify($payload, $signature, $pubKey, OPENSSL_ALGO_SHA256);
    if ($result !== 1) {
        json_abort(401, 'SIGNATURE_INVALID');
    }

    unset($_SESSION['challenge_nonce'], $_SESSION['challenge_issued_at']);

    return [$username, $pwdhash];
}

function validate_input(): array {
    $username = trim($_POST['username'] ?? '');
    if ($username === '')        json_abort(400, 'MISSING_FIELDS');
    if (strlen($username) > 64) json_abort(400, 'INPUT_TOO_LONG');
    // ユーザー名に許可外文字が含まれる場合は即拒否
    if (!preg_match('/^[a-zA-Z0-9_\-\.]{1,24}$/', $username)) json_abort(400, 'INVALID_USERNAME');
    return verify_signed_payload($username);
}

// ─── JSON I/O ─────────────────────────────────────────────────────────────────
function load_users_json(): array {
    if (!is_file(USERS_FILE)) return [];
    $fp = @fopen(USERS_FILE, 'r');
    if ($fp === false) return [];
    if (!flock($fp, LOCK_SH)) { fclose($fp); return []; }
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if ($raw === false || $raw === '') return [];
    $json = json_decode($raw, true);
    return (is_array($json) && isset($json['data'])) ? $json['data'] : [];
}

function save_users_json(array $users): bool {
    $fp = @fopen(USERS_FILE, 'c+');
    if ($fp === false) {
        error_log('SAVE_USERS_OPEN_FAIL: ' . USERS_FILE);
        return false;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        return false;
    }
    $content = stream_get_contents($fp);
    $current_data = [];
    if (!empty($content)) $current_data = json_decode($content, true) ?: [];
    $current_data['data'] = array_values($users);
    ftruncate($fp, 0);
    rewind($fp);
    $encoded = json_encode($current_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    $ok = (fwrite($fp, $encoded) !== false);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$ok) error_log('SAVE_USERS_WRITE_FAIL: ' . USERS_FILE);
    return $ok;
}

// ─── セッション整合性 ─────────────────────────────────────────────────────────
function verify_session_integrity(): bool {
    if (empty($_SESSION['authenticated'])) return false;
    if (!empty($_SESSION['is_fallback']))  return true;
    if (!empty($_SESSION['is_guest']))     return check_guest_integrity_by_token(
        $_SESSION['guest_id'] ?? '', $_SESSION['guest_session_token'] ?? ''
    );

    $uid      = $_SESSION['user_id'] ?? '';
    $sessHash = $_SESSION['pwdhash'] ?? '';

    foreach (load_users_json() as $u) {
        if (($u['id'] ?? '') !== $uid) continue;
        $stored = $u['pwdhash'] ?? '';
        if ($stored === '') return false;
        return hash_equals(strtolower($stored), $sessHash);
    }
    return false;
}

// ─── 認証ロジック ─────────────────────────────────────────────────────────────
function check_fallback(string $username, string $pwdhash): bool {
    // いずれか未設定ならフォールバック認証を完全無効化
    if (FB_USER === '' || FB_HASH === '' || FB_WM_KEY === '' || FB_USER_ID === '') {
        return false;
    }
    if (!preg_match('/^[0-9a-f]{128}$/', FB_HASH)) {
        error_log('FALLBACK_DISABLED_INVALID_HASH_FORMAT');
        return false;
    }

    $wm  = $_POST['is_webmaster'] ?? '';
    $uid = $_POST['user_id']      ?? '';
    if (!is_string($wm) || !is_string($uid)) return false;
    if ($username !== FB_USER)               return false;
    if (!hash_equals(FB_HASH,    $pwdhash))  return false;
    if (!hash_equals(FB_WM_KEY,  $wm))       return false;
    if (!hash_equals(FB_USER_ID, $uid))      return false;
    return true;
}

function check_users_json(string $username, string $pwdhash): ?array {
    foreach (load_users_json() as $entry) {
        if (!is_array($entry)) continue;
        if (($entry['name'] ?? '') !== $username) continue;
        // ユーザー名一致: フィールド整合性を検証
        $id     = $entry['id']     ?? '';
        $stored = $entry['pwdhash'] ?? '';
        if ($id === '' || !preg_match('/^[0-9a-f]{128}$/', $stored)) {
            return ['corrupt' => true];
        }
        if (hash_equals(strtolower($stored), $pwdhash)) {
            return ['id' => $id, 'pwdhash' => strtolower($stored)];
        }
        break;
    }
    return null;
}

function check_guests_json(string $username, string $pwdhash): ?array {
    if (!probe_guest_enc_key()) return ['key_broken' => true];
    foreach (load_guests() as $g) {
        if (!is_array($g)) continue;
        if (($g['name'] ?? '') !== $username) continue;
        // ユーザー名一致: レコード整合性を検証
        $integrity = check_guest_record_integrity($g);
        if ($integrity !== 'ok') return ['corrupt' => true];
        $plain = guest_decrypt($g['enc_pwd']);
        if (hash_equals(strtolower(hash('sha512', $plain)), $pwdhash)) {
            return ['id' => $g['id']];
        }
        break;
    }
    return null;
}

// ─── ルーティング ─────────────────────────────────────────────────────────────

// ─── PoW ──────────────────────────────────────────────────────────────────────
// Hashcash型: SHA-256(salt + ":" + nonce) の先頭 POW_DIFFICULTY ビットが0であること
// クライアントはnonceをインクリメントしながら条件を満たすまで試行する

// 1時間ウィンドウのアクセス数を読み書きし、現在のPoW難易度を返す
// difficulty = BASE + floor(log2(1 + count / SCALE))
// count=0→12bit, count≈10→13bit, count≈100→18bit, count≈300→20bit（上限）
function get_pow_difficulty(): int {
    $path = POW_HOUR_FILE;
    $dir  = dirname($path);
    if (!is_dir($dir)) mkdir($dir, 0700, true);

    $fp = @fopen($path, 'c+');
    if ($fp === false) return POW_BASE_DIFFICULTY; // 読めない場合は最低難易度

    if (!flock($fp, LOCK_EX)) { fclose($fp); return POW_BASE_DIFFICULTY; }

    $now  = time();
    $raw  = stream_get_contents($fp);
    $data = ['count' => 0, 'since' => $now];
    if ($raw) {
        $tmp = json_decode($raw, true);
        // 1時間ウィンドウ内なら既存カウントを使用、期限切れなら初期化
        if (is_array($tmp) && ($now - (int)($tmp['since'] ?? 0)) < 3600) {
            $data = $tmp;
        }
    }
    $data['count']++;
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    // difficulty = BASE + floor(TARGET_BITS * log2(1 + count/SCALE) / log2(1 + TARGET_COUNT/SCALE))
    // count=TARGET_COUNTで正確にMAX_DIFFICULTYに到達、count=5以下はBASEを維持
    $targetBits = POW_MAX_DIFFICULTY - POW_BASE_DIFFICULTY;
    $denom      = log(1 + POW_TARGET_COUNT / POW_SCALE, 2);
    $raw        = $targetBits * log(1 + $data['count'] / POW_SCALE, 2) / $denom;
    $diff       = POW_BASE_DIFFICULTY + (int)floor($raw);
    return min($diff, POW_MAX_DIFFICULTY);
}

function pow_verify_hash(string $salt, string $nonce, int $difficulty): bool {
    if (!preg_match('/^[0-9]+$/', $nonce)) return false;
    $hash     = hash('sha256', $salt . ':' . $nonce, true); // rawバイナリ
    $fullBytes = intdiv($difficulty, 8);
    $remBits   = $difficulty % 8;
    for ($i = 0; $i < $fullBytes; $i++) {
        if (ord($hash[$i]) !== 0) return false;
    }
    if ($remBits > 0) {
        if ((ord($hash[$fullBytes]) >> (8 - $remBits)) !== 0) return false;
    }
    return true;
}

// GET: PoWチャレンジ発行
if (isset($_GET['pow_challenge'])) {
    check_rate_limit();
    start_session_stable();
    $difficulty = get_pow_difficulty();
    $salt = bin2hex(random_bytes(16));
    $_SESSION['pow_salt']       = $salt;
    $_SESSION['pow_issued_at']  = time();
    $_SESSION['pow_difficulty'] = $difficulty;
    unset($_SESSION['pow_token']); // 既存トークンを無効化
    session_write_close();
    echo json_encode(['ok' => true, 'salt' => $salt, 'difficulty' => $difficulty]);
    exit;
}

// POST: PoW検証 → トークン発行
if (isset($_GET['pow_verify'])) {
    if (!$isPost) json_abort(405, 'METHOD_NOT_ALLOWED');
    check_rate_limit();
    start_session_stable();

    $salt       = $_SESSION['pow_salt']       ?? '';
    $difficulty = (int)($_SESSION['pow_difficulty'] ?? POW_BASE_DIFFICULTY);
    $issuedAt   = (int)($_SESSION['pow_issued_at']  ?? 0);
    if ($salt === '' || (time() - $issuedAt) > POW_TTL) {
        json_abort(400, 'POW_CHALLENGE_EXPIRED');
    }

    $nonce = trim($_POST['nonce'] ?? '');
    if ($nonce === '' || strlen($nonce) > 20) json_abort(400, 'POW_INVALID_NONCE');

    if (!pow_verify_hash($salt, $nonce, $difficulty)) {
        error_log('POW_FAIL ip=' . get_client_ip());
        json_abort(403, 'POW_FAILED');
    }

    // 検証成功: セッションにトークンを保存してチャレンジを消費
    $token = bin2hex(random_bytes(32));
    unset($_SESSION['pow_salt'], $_SESSION['pow_issued_at']);
    $_SESSION['pow_token']    = $token;
    $_SESSION['pow_issued']   = time();
    session_write_close();
    echo json_encode(['ok' => true, 'pow_token' => $token]);
    exit;
}

// GET: チャレンジ発行（レートリミット適用）
if (isset($_GET['challenge'])) {
    check_rate_limit();
    start_session_stable();
    $nonce = bin2hex(random_bytes(32));
    $_SESSION['challenge_nonce']     = $nonce;
    $_SESSION['challenge_issued_at'] = time();
    session_write_close();
    echo json_encode(['ok' => true, 'nonce' => $nonce]);
    exit;
}

// GET: セッション確認
if (isset($_GET['check'])) {
    init_session();
    bind_session();

    if (!empty($_SESSION['authenticated']) && !verify_session_integrity()) {
        session_unset();
        session_destroy();
        echo json_encode(['ok' => false, 'authenticated' => false, 'reason' => 'SESSION_INVALIDATED']);
        exit;
    }

    if (empty($_SESSION['csrf_token'])) {
        $tok = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $tok;
        setcookie('csrf_token', $tok, [
            'path'     => '/',
            'secure'   => true,
            'httponly' => false,
            'samesite' => 'Strict',
        ]);
    }
    $isAuth     = !empty($_SESSION['authenticated']);
    $isFallback = !empty($_SESSION['is_fallback']);
    $uname      = $_SESSION['username'] ?? '';
    session_write_close();
    echo json_encode($isAuth
        ? ['ok' => true,  'authenticated' => true,  'username' => $uname,
           'redirect' => $isFallback ? 'manager/admin.php' : 'index.php']
        : ['ok' => false, 'authenticated' => false]
    );
    exit;
}

// GET: ログアウト（再生成不要 — start_session_stable を使う）
if (isset($_GET['logout'])) {
    start_session_stable();
    if (!empty($_SESSION['is_guest']) && !empty($_SESSION['guest_id'])) {
        clear_guest_session_token($_SESSION['guest_id']);
    }
    session_unset();
    session_destroy();
    echo json_encode(['ok' => true]);
    exit;
}

// GET: パスワード変更チャレンジ（認証済み専用）
if (isset($_GET['change_pwd_challenge'])) {
    check_rate_limit();
    start_session_stable();
    if (empty($_SESSION['authenticated']) || !empty($_SESSION['is_fallback']) || !empty($_SESSION['is_guest'])) {
        json_abort(403, 'FORBIDDEN');
    }
    bind_session();
    $nonce = bin2hex(random_bytes(32));
    $_SESSION['chpwd_challenge_nonce']     = $nonce;
    $_SESSION['chpwd_challenge_issued_at'] = time();
    session_write_close();
    echo json_encode(['ok' => true, 'nonce' => $nonce]);
    exit;
}

// POST: パスワード変更
if (isset($_GET['change_pwd'])) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_abort(405, 'METHOD_NOT_ALLOWED');

    check_rate_limit();
    init_session();

    if (empty($_SESSION['authenticated']) || !empty($_SESSION['is_fallback']) || !empty($_SESSION['is_guest'])) {
        json_abort(403, 'FORBIDDEN');
    }
    bind_session();
    if (!verify_session_integrity()) {
        session_unset(); session_destroy();
        json_abort(401, 'SESSION_INVALIDATED');
    }

    $provided = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token']) || !is_string($provided) ||
        !hash_equals($_SESSION['csrf_token'], $provided)) {
        json_abort(403, 'CSRF_MISMATCH');
    }

    $mode = $_POST['mode'] ?? '';

    if ($mode === 'verify_current') {
        $issuedAt = (int)($_SESSION['chpwd_challenge_issued_at'] ?? 0);
        if ($issuedAt === 0 || (time() - $issuedAt) > CHALLENGE_TTL) json_abort(400, 'CHALLENGE_EXPIRED');

        $nonce        = $_SESSION['chpwd_challenge_nonce'] ?? '';
        $clientPubB64 = $_POST['client_pubkey'] ?? '';
        $signatureB64 = $_POST['signature']     ?? '';
        $postedNonce  = $_POST['nonce']         ?? '';
        $curHash      = strtolower(trim($_POST['pwdhash'] ?? ''));

        if ($nonce === '' || $clientPubB64 === '' || $signatureB64 === '') json_abort(400, 'MISSING_CRYPTO_FIELDS');
        if (!is_string($postedNonce) || !hash_equals($nonce, $postedNonce)) json_abort(400, 'NONCE_MISMATCH');
        if (!preg_match('/^[0-9a-f]{128}$/', $curHash))                    json_abort(400, 'INVALID_HASH_FORMAT');

        if (strlen($clientPubB64) > 1024 || strlen($signatureB64) > 1024) json_abort(400, 'PAYLOAD_TOO_LARGE');

        $spkiDer = base64_decode($clientPubB64, true);
        if ($spkiDer === false) json_abort(400, 'INVALID_CLIENT_PUBKEY_ENCODING');
        $pubKeyPem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spkiDer), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
        $pubKey = openssl_pkey_get_public($pubKeyPem);
        if ($pubKey === false) json_abort(400, 'INVALID_CLIENT_PUBKEY');

        $details = openssl_pkey_get_details($pubKey);
        if (($details['type'] ?? -1) !== OPENSSL_KEYTYPE_RSA) json_abort(400, 'WRONG_KEY_TYPE');
        if (($details['bits'] ?? 0) < 2048)                   json_abort(400, 'RSA_KEY_TOO_SHORT');

        $signature = base64_decode($signatureB64, true);
        if ($signature === false) json_abort(400, 'INVALID_SIGNATURE_ENCODING');
        if (openssl_verify($nonce . ':' . $curHash, $signature, $pubKey, OPENSSL_ALGO_SHA256) !== 1) {
            json_abort(401, 'SIGNATURE_INVALID');
        }

        unset($_SESSION['chpwd_challenge_nonce'], $_SESSION['chpwd_challenge_issued_at']);

        $uid   = $_SESSION['user_id'] ?? '';
        $match = false;
        foreach (load_users_json() as $u) {
            if (($u['id'] ?? '') !== $uid) continue;
            $stored = $u['pwdhash'] ?? '';
            if ($stored !== '' && hash_equals(strtolower($stored), $curHash)) $match = true;
            break;
        }
        if (!$match) {
            usleep(random_int(150000, 300000));
            json_abort(401, 'WRONG_CURRENT_PASSWORD');
        }

        $stepToken = bin2hex(random_bytes(32));
        $_SESSION['chpwd_step_token']  = $stepToken;
        $_SESSION['chpwd_step_issued'] = time();
        session_write_close();

        echo json_encode(['ok' => true, 'step_token' => $stepToken]);
        exit;

    } elseif ($mode === 'set_new') {
        $stepToken  = $_POST['step_token'] ?? '';
        $sessToken  = $_SESSION['chpwd_step_token']  ?? '';
        $stepIssued = (int)($_SESSION['chpwd_step_issued'] ?? 0);

        if (!is_string($stepToken) || empty($sessToken) || !hash_equals($sessToken, $stepToken)) {
            json_abort(403, 'INVALID_STEP_TOKEN');
        }
        if ((time() - $stepIssued) > 600) json_abort(400, 'STEP_TOKEN_EXPIRED');

        $newHash = strtolower(trim($_POST['new_pwdhash'] ?? ''));
        if (!preg_match('/^[0-9a-f]{128}$/', $newHash)) json_abort(400, 'INVALID_HASH_FORMAT');

        if (hash_equals($_SESSION['pwdhash'] ?? '', $newHash)) json_abort(400, 'SAME_AS_CURRENT');

        $uid   = $_SESSION['user_id'] ?? '';
        $users = load_users_json();
        $saved = false;
        foreach ($users as &$u) {
            if (($u['id'] ?? '') !== $uid) continue;
            $u['pwdhash'] = $newHash;
            $saved = true;
            break;
        }
        unset($u);

        if (!$saved) json_abort(404, 'USER_NOT_FOUND');
        if (!save_users_json($users)) json_abort(500, 'SAVE_FAILED');

        $_SESSION['pwdhash'] = $newHash;
        unset($_SESSION['chpwd_step_token'], $_SESSION['chpwd_step_issued']);

        $newTok = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $newTok;
        setcookie('csrf_token', $newTok, ['path'=>'/','secure'=>true,'httponly'=>false,'samesite'=>'Strict']);
        session_write_close();

        echo json_encode(['ok' => true]);
        exit;

    } else {
        json_abort(400, 'UNKNOWN_MODE');
    }
}

// POST: ログイン認証
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_abort(405, 'METHOD_NOT_ALLOWED');
}

check_rate_limit();
init_session();
validate_csrf();

// PoWトークン検証（login.phpで事前に解決済みであること）
$powToken    = $_POST['pow_token'] ?? '';
$sessPowTok  = $_SESSION['pow_token']  ?? '';
$sessPowTime = (int)($_SESSION['pow_issued'] ?? 0);
if ($sessPowTok === '' || $powToken === '' ||
    !hash_equals($sessPowTok, $powToken) ||
    (time() - $sessPowTime) > POW_TOKEN_TTL) {
    error_log('POW_TOKEN_INVALID ip=' . get_client_ip());
    json_abort(403, 'POW_TOKEN_REQUIRED');
}
unset($_SESSION['pow_token'], $_SESSION['pow_issued']);

[$username, $pwdhash] = validate_input();

$authenticated = false;
$isFallback    = false;
$userRecord    = null;
$guestRecord   = null;

if (check_fallback($username, $pwdhash)) {
    $authenticated = true;
    $isFallback    = true;
} else {
    $userRecord = check_users_json($username, $pwdhash);
    if ($userRecord !== null) {
        if (!empty($userRecord['corrupt'])) {
            usleep(random_int(150000, 300000));
            json_abort(401, 'USER_CORRUPT');
        }
        $authenticated = true;
    } else {
        $guestRecord = check_guests_json($username, $pwdhash);
        if ($guestRecord !== null) {
            if (!empty($guestRecord['key_broken'])) {
                usleep(random_int(150000, 300000));
                json_abort(401, 'GUEST_KEY_BROKEN');
            }
            if (!empty($guestRecord['corrupt'])) {
                usleep(random_int(150000, 300000));
                json_abort(401, 'GUEST_CORRUPT');
            }
            $authenticated = true;
        }
    }
}

if (!$authenticated) {
    usleep(random_int(150000, 300000));
    check_server_lockout();
    record_fail();
    $lockUntil = (int)($_SESSION['lock_until'] ?? 0);
    if ($lockUntil > time()) {
        json_abort(429, 'LOCKED:' . ($lockUntil - time()));
    }
    error_log(sprintf('AUTH_FAIL ip=%s user=%s', get_client_ip(), $username));
    json_abort(401, 'AUTHENTICATION_FAILED');
}

session_regenerate_id(true);
clear_fails();
$_SESSION['authenticated'] = true;
$_SESSION['username']      = $username;
$_SESSION['is_fallback']   = $isFallback;
$_SESSION['login_at']      = time();
$_SESSION['_ip']           = get_client_ip();
$_SESSION['_ua']           = ua_fingerprint();
if (!$isFallback && $userRecord !== null) {
    $_SESSION['user_id'] = $userRecord['id'];
    $_SESSION['pwdhash'] = $userRecord['pwdhash'];
}
if ($guestRecord !== null) {
    $_SESSION['is_guest']            = true;
    $_SESSION['guest_id']            = $guestRecord['id'];
    $_SESSION['guest_session_token'] = update_guest_session_token($guestRecord['id']);
}

$newTok = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $newTok;
setcookie('csrf_token', $newTok, [
    'path'     => '/',
    'secure'   => true,
    'httponly' => false,
    'samesite' => 'Strict',
]);

$redirect = $isFallback ? 'manager/admin.php' : 'index.php';

// users.jsonにログイン時刻を記録
if ($isFallback) {
    // 管理者: トップレベルのadmin_lastLoginTimeを更新
    $fp = @fopen(USERS_FILE, 'c+');
    if ($fp !== false && flock($fp, LOCK_EX)) {
        $raw  = stream_get_contents($fp);
        $json = ($raw !== '' && $raw !== false) ? (json_decode($raw, true) ?? []) : [];
        $json['admin_lastLoginTime'] = $_SESSION['login_at'];
        ftruncate($fp, 0); rewind($fp);
        fwrite($fp, json_encode($json, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        fflush($fp); flock($fp, LOCK_UN);
    }
    if ($fp !== false) fclose($fp);
} elseif ($userRecord !== null) {
    // 通常ユーザー: data配列内のlastLoginTimeを更新
    $uid   = $_SESSION['user_id'];
    $users = load_users_json();
    foreach ($users as &$u) {
        if (($u['id'] ?? '') !== $uid) continue;
        $u['lastLoginTime'] = $_SESSION['login_at'];
        break;
    }
    unset($u);
    save_users_json($users);
}

session_write_close();
echo json_encode(['ok' => true, 'redirect' => $redirect]);
exit;
