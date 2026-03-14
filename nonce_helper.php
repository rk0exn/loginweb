<?php
declare(strict_types=1);

function generate_nonce(): string {
    return base64_encode(random_bytes(18));
}

function emit_csp(string $nonce, string $connectSrc = "'self'"): void {
    $n = "nonce-{$nonce}";
    // 許可ホワイトリストに static.cloudflareinsights.com を含めないことで
    // Cloudflare Web Analytics の JS読み込み・ビーコン送信を両方ブロックする。
    // script-src / script-src-elem: https://code.activetk.jp のみ外部を許可
    // connect-src: $connectSrc のみ（呼び出し元が 'self' + 必要な外部オリジンを渡す）
    header(
        "Content-Security-Policy: " .
        "default-src 'self'; " .
        "script-src 'self' '{$n}' https://code.activetk.jp; " .
        "script-src-elem 'self' '{$n}' https://code.activetk.jp; " .
        "style-src 'self' '{$n}'; " .
        "style-src-elem 'self' '{$n}'; " .
        "worker-src blob:; " .
        "connect-src {$connectSrc}; " .
        "frame-ancestors 'none'; " .
        "base-uri 'none'; " .
        "form-action 'self';"
    );
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    // no-transform: Cloudflare等のCDNがHTMLを書き換えてスクリプトを注入するのを抑止する
    // Cloudflareはこのヘッダーを尊重してRocket Loader・Web Analyticsの注入を行わない
    header('Cache-Control: no-store, no-transform');
}