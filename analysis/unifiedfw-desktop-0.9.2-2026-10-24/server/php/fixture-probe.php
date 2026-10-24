<?php
declare(strict_types=1);
// Temporary bounded diagnostic echo. No include, storage, credentials or commands.
const UFW_EXPIRES_UTC = '2026-10-26T05:47:49Z';
function ufw_reply(int $status, array $payload): void {
    $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if ($body === false) { http_response_code(500); exit; }
    http_response_code($status);
    header_remove('X-Powered-By');
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}
if (time() >= strtotime(UFW_EXPIRES_UTC)) {
    ufw_reply(410, array('error' => 'temporary_probe_expired', 'expires_utc' => UFW_EXPIRES_UTC));
}
$method = $_SERVER['REQUEST_METHOD'] ?? '';
if ($method === 'GET') {
    ufw_reply(200, array('service' => 'UnifiedFW HTTPS lab', 'ready' => true,
        'protocol' => 'unifiedfw-traffic-1', 'expires_utc' => UFW_EXPIRES_UTC));
}
if ($method !== 'POST') {
    header('Allow: GET, POST');
    ufw_reply(405, array('error' => 'method_not_allowed'));
}
$type = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
if ($type !== 'application/json') { ufw_reply(415, array('error' => 'json_required')); }
$length = $_SERVER['CONTENT_LENGTH'] ?? '';
if ($length !== '' && (preg_match('/\A[0-9]{1,5}\z/', (string)$length) !== 1 || strlen((string)$length) > 5 || (int)$length > 1024)) {
    ufw_reply(413, array('error' => 'request_too_large'));
}
$raw = file_get_contents('php://input', false, null, 0, 1025);
if ($raw === false || strlen($raw) > 1024) { ufw_reply(413, array('error' => 'request_too_large')); }
try { $q = json_decode($raw, true, 8, JSON_THROW_ON_ERROR); }
catch (Throwable $e) { ufw_reply(400, array('error' => 'invalid_json')); }
if (!is_array($q)) { ufw_reply(400, array('error' => 'invalid_schema')); }
$keys = array_keys($q); sort($keys);
if ($keys !== array('kind', 'nonce', 'request_id', 'role') || $q['kind'] !== 'unifiedfw-traffic-1'
    || !is_string($q['nonce']) || preg_match('/\A[a-f0-9]{64}\z/', $q['nonce']) !== 1
    || !is_string($q['request_id']) || preg_match('/\A[a-f0-9]{32}\z/', $q['request_id']) !== 1
    || !in_array($q['role'], array('A', 'B', 'REF'), true)) {
    ufw_reply(400, array('error' => 'invalid_schema'));
}
// REMOTE_ADDR may belong to a hosting proxy. Never trust X-Forwarded-For here.
$peer = $_SERVER['REMOTE_ADDR'] ?? '';
if (filter_var($peer, FILTER_VALIDATE_IP) === false) { ufw_reply(503, array('error' => 'peer_unavailable')); }
$q['observed_peer'] = $peer;
ufw_reply(200, $q);
