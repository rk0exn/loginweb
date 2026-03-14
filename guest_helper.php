<?php
declare(strict_types=1);

if (!defined('GUESTS_FILE'))    define('GUESTS_FILE',    '/var/www/private/guests.json');
if (!defined('GUEST_KEY_FILE')) define('GUEST_KEY_FILE', '/var/www/private/guest_enc_key');
if (!defined('GUEST_MAX'))      define('GUEST_MAX',      10);
if (!defined('PWD_MIN_LEN'))    define('PWD_MIN_LEN',    8);

function get_guest_enc_key(): string {
    if (is_file(GUEST_KEY_FILE)) {
        $k = trim((string)@file_get_contents(GUEST_KEY_FILE));
        if (strlen($k) === 64) return $k;
    }
    $k = bin2hex(random_bytes(32));
    @file_put_contents(GUEST_KEY_FILE, $k, LOCK_EX);
    @chmod(GUEST_KEY_FILE, 0600);
    return $k;
}

// 鍵ファイルが存在し有効な形式か確認する（自動生成しない）
function probe_guest_enc_key(): bool {
    if (!is_file(GUEST_KEY_FILE)) return false;
    $k = trim((string)@file_get_contents(GUEST_KEY_FILE));
    return strlen($k) === 64 && ctype_xdigit($k);
}

// 単一ゲストレコードの整合性を検証する
// 戻り値: 'ok' | 'missing_fields' | 'bad_enc_format' | 'decrypt_failed'
function check_guest_record_integrity(array $g): string {
    if (empty($g['id']) || empty($g['name']) || empty($g['enc_pwd'])) return 'missing_fields';
    $parts = explode(':', $g['enc_pwd'], 2);
    if (count($parts) !== 2) return 'bad_enc_format';
    $iv = base64_decode($parts[0], true);
    $ct = base64_decode($parts[1], true);
    if ($iv === false || $ct === false || strlen($iv) !== 16) return 'bad_enc_format';
    if (guest_decrypt($g['enc_pwd']) === null) return 'decrypt_failed';
    return 'ok';
}

function guest_encrypt(string $plaintext): string {
    $key = hex2bin(get_guest_enc_key());
    $iv  = random_bytes(16);
    $ct  = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv) . ':' . base64_encode((string)$ct);
}

function guest_decrypt(string $enc): ?string {
    $parts = explode(':', $enc, 2);
    if (count($parts) !== 2) return null;
    $iv = base64_decode($parts[0], true);
    $ct = base64_decode($parts[1], true);
    if ($iv === false || $ct === false || strlen($iv) !== 16) return null;
    $key    = hex2bin(get_guest_enc_key());
    $result = openssl_decrypt($ct, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $result === false ? null : $result;
}

function load_guests(): array {
    if (!is_file(GUESTS_FILE)) return [];
    $fp = @fopen(GUESTS_FILE, 'r');
    if ($fp === false) return [];
    if (!flock($fp, LOCK_SH)) { fclose($fp); return []; }
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    if (!$raw) return [];
    $d = json_decode($raw, true);
    return is_array($d) ? $d : [];
}

function save_guests(array $guests): bool {
    $fp = @fopen(GUESTS_FILE, 'c+');
    if ($fp === false) return false;
    if (!flock($fp, LOCK_EX)) { fclose($fp); return false; }
    ftruncate($fp, 0);
    rewind($fp);
    $ok = (fwrite($fp, json_encode(array_values($guests), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) !== false);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $ok;
}

// ログイン成功時: 新しいセッショントークンを発行し guests.json を更新する。
// 旧セッションは ws.php のトークン照合で force_logout される（単一セッション強制）。
function update_guest_session_token(string $guestId): string {
    $token  = bin2hex(random_bytes(32));
    $guests = load_guests();
    foreach ($guests as &$g) {
        if (($g['id'] ?? '') !== $guestId) continue;
        $g['session_token'] = $token;
        $g['lastLoginTime'] = time();
        break;
    }
    unset($g);
    save_guests($guests);
    return $token;
}

function clear_guest_session_token(string $guestId): void {
    $guests = load_guests();
    foreach ($guests as &$g) {
        if (($g['id'] ?? '') !== $guestId) continue;
        $g['session_token'] = null;
        break;
    }
    unset($g);
    save_guests($guests);
}

function check_guest_integrity_by_token(string $guestId, string $sessToken): bool {
    if ($sessToken === '') return false;
    foreach (load_guests() as $g) {
        if (($g['id'] ?? '') !== $guestId) continue;
        $stored = $g['session_token'] ?? '';
        if ($stored === '' || $stored === null) return false;
        return hash_equals((string)$stored, $sessToken);
    }
    return false;
}