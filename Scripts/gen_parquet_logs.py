#!/usr/bin/env python3
"""
gen_parquet_logs.py — unstructured application logs, one column: `message`.

Emits a single-column Parquet file whose only field is a raw log line, mixing
the formats a real banking platform actually produces: Log4j/Logback, nginx
combined access logs, syslog, HikariCP pool warnings, JVM GC lines, Kafka
consumer output, embedded JSON, HAProxy, Envoy, WAF/ModSecurity, IIS W3C,
CEF/SIEM, Postgres, Redis, and multi-line Java stack traces.

Nothing is pre-parsed. The point is to force DISSECT / GROK / regex work at
query time, which is the interesting part of querying object storage from ES|QL.

CLIENT IPs
    Normal client traffic is drawn from 10.30.255.0 .. 10.50.255.0.
    One host, 10.49.110.17, is deliberately over-represented (~3% of all
    client-IP-bearing lines) and behaves badly: credential stuffing, enumeration
    of accountIds, path traversal, SQLi probes, off-hours activity, WAF blocks,
    and 401/403/429 bursts. It is intended to be found by alert rules and ML
    anomaly detection jobs, NOT by a flag column -- there is no such column.

Account IDs (1..35000) and the Fraud-Workshop persona accounts appear inside
the text, so parsed logs can be correlated back to the transaction data.

A recurring incident is woven in: roughly once a week the connection pool
saturates and produces a burst of WARN/ERROR/stack traces across services --
useful for log rate analysis and change point detection.

Usage:
    python3 gen_parquet_logs.py
    python3 gen_parquet_logs.py --rows 2000000 --days 30 --out app_logs.parquet
    python3 gen_parquet_logs.py --incidents 0        # clean baseline, no bursts
    python3 gen_parquet_logs.py --suspicious-rate 0.06 --campaigns 6
    python3 gen_parquet_logs.py --suspicious-rate 0   # no malicious actor
"""
import argparse
import ipaddress
import os
import random
from datetime import datetime, timedelta, timezone

import pyarrow as pa
import pyarrow.parquet as pq

MAX_ACCOUNT_ID = 35_000
PERSONA_ACCOUNTS = (
    list(range(2, 22, 2))
    + [32687, 16384, 8192, 4096, 2048]
    + [1594, 21162, 1874, 2718, 3141, 1618, 1414]
)

# ---------------------------------------------------------------------------
# Client IP space
# ---------------------------------------------------------------------------
CLIENT_IP_LOW = int(ipaddress.IPv4Address("10.30.255.0"))
CLIENT_IP_HIGH = int(ipaddress.IPv4Address("10.50.255.0"))
SUSPICIOUS_IP = "10.49.110.17"

# A stable pool of "regular" clients so per-IP baselines are learnable by ML
# jobs. Without this, every line would be a unique IP and no entity would have
# a history to be anomalous against.
_POOL_SIZE = 900
CLIENT_POOL = []
_CHATTY = []


def _build_client_pool(rng):
    global CLIENT_POOL, _CHATTY
    CLIENT_POOL = [str(ipaddress.IPv4Address(rng.randrange(CLIENT_IP_LOW,
                                                           CLIENT_IP_HIGH + 1)))
                   for _ in range(_POOL_SIZE)]
    # a few high-volume legitimate clients (branch NAT gateways, mobile edge)
    _CHATTY = rng.sample(CLIENT_POOL, 25)


def client_ip(suspicious_rate, force_normal=False):
    """Client-side IP. Draws SUSPICIOUS_IP at an elevated rate."""
    if not force_normal and random.random() < suspicious_rate:
        return SUSPICIOUS_IP
    if random.random() < 0.35:
        return random.choice(_CHATTY)
    return random.choice(CLIENT_POOL)


def ext_ip():
    """Non-client / internet-facing address, outside the client range."""
    return (f"{random.choice([66, 74, 104, 172, 185, 203])}."
            f"{random.randrange(0, 255)}.{random.randrange(0, 255)}."
            f"{random.randrange(1, 254)}")


HOSTS = ["ip-10-42-1-17", "ip-10-42-1-38", "ip-10-42-2-9", "ip-10-42-2-51",
         "ip-10-42-3-22", "atx-app-01", "atx-app-02", "atx-batch-01",
         "atx-app-03", "atx-edge-01", "atx-edge-02", "atx-db-01"]
SERVICES = ["auth-service", "transfer-service", "account-service",
            "payment-gateway", "ledger-api", "notification-service",
            "fraud-scoring", "statement-batch", "session-service",
            "payee-service", "card-service", "onboarding-api"]
PACKAGES = {
    "auth-service": "c.a.b.auth.LoginController",
    "transfer-service": "c.a.b.txn.WireTransferService",
    "account-service": "c.a.b.acct.AccountQueryService",
    "payment-gateway": "c.a.b.pay.GatewayDispatcher",
    "ledger-api": "c.a.b.ledger.PostingEngine",
    "notification-service": "c.a.b.notify.SmsDispatcher",
    "fraud-scoring": "c.a.b.risk.ScoreEvaluator",
    "statement-batch": "c.a.b.batch.StatementJob",
    "session-service": "c.a.b.session.TokenManager",
    "payee-service": "c.a.b.payee.PayeeRegistry",
    "card-service": "c.a.b.card.CardLifecycle",
    "onboarding-api": "c.a.b.kyc.OnboardingFlow",
}
ENDPOINTS = ["/api/v2/accounts", "/api/v2/transfers", "/api/v2/auth/login",
             "/api/v2/auth/refresh", "/api/v2/statements", "/api/v2/payees",
             "/api/v1/balance", "/health", "/actuator/prometheus",
             "/api/v2/cards", "/api/v2/cards/activate", "/api/v2/profile",
             "/api/v2/notifications", "/api/v2/documents", "/api/v1/fx/rates"]
# Paths the suspicious host probes for. None of these are normal traffic.
RECON_PATHS = [
    "/api/v2/accounts?accountId=%d",
    "/api/v2/../../etc/passwd",
    "/api/v2/admin/users",
    "/actuator/env", "/actuator/heapdump", "/.env", "/.git/config",
    "/api/v1/internal/ledger/export",
    "/api/v2/auth/login", "/api/v2/auth/login", "/api/v2/auth/login",
    "/wp-login.php", "/phpmyadmin/", "/api/v2/accounts%%2F..%%2Fadmin",
    "/api/v2/statements?accountId=%d&format=csv",
]
SQLI_PROBES = [
    "' OR '1'='1", "1' UNION SELECT NULL,NULL--", "'; DROP TABLE accounts--",
    "1 AND SLEEP(5)", "%27%20OR%201%3D1--", "admin'--",
]
AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.5",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/126.0",
    "AustinBank/4.12.1 (iPhone; iOS 18.2)",
    "AustinBank/4.11.0 (Android 15; Pixel 8)",
    "AustinBank/4.9.3 (Android 14; SM-S918U)",
    "python-requests/2.32.3",
    "curl/8.7.1",
]
# The suspicious host cycles through tooling and spoofed agents.
BAD_AGENTS = [
    "python-requests/2.31.0", "curl/7.81.0", "Go-http-client/1.1",
    "sqlmap/1.8.2#stable (https://sqlmap.org)", "Hydra/9.5",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0",
]
USERS = ["jmartinez", "bkozlov", "hsidorov", "cma", "vmoeller", "dlu", "dtian",
         "ycho", "apatel", "rwilliams", "svc_ledger", "svc_batch", "tnguyen",
         "kobrien", "mfernandez", "lschmidt", "svc_recon", "pdavis"]
# Accounts the attacker targets, drawn partly from the fraud personas so the
# log data ties back to the transaction data.
TARGET_USERS = ["admin", "administrator", "root", "svc_ledger", "svc_batch",
                "jmartinez", "test", "oracle", "backup", "svc_recon"]
SQL = [
    "SELECT * FROM accounts WHERE account_id = ?",
    "SELECT balance, status FROM ledger_positions WHERE account_id = ? FOR UPDATE",
    "UPDATE ledger_positions SET balance = balance - ? WHERE account_id = ?",
    "INSERT INTO transaction_journal (account_id, amount, event_type) VALUES (?, ?, ?)",
    "SELECT COUNT(*) FROM wire_queue WHERE status = 'PENDING'",
    "SELECT p.* FROM payees p JOIN accounts a ON a.id = p.account_id WHERE a.id = ?",
    "DELETE FROM session_tokens WHERE expires_at < ?",
]
TRACE_EXCEPTIONS = [
    ("java.sql.SQLTransientConnectionException",
     "HikariPool-1 - Connection is not available, request timed out after 30001ms"),
    ("org.springframework.dao.QueryTimeoutException",
     "Query did not complete within 15000ms"),
    ("java.net.SocketTimeoutException", "Read timed out"),
    ("com.austinbank.ledger.PostingException",
     "Ledger posting rejected: insufficient available balance"),
    ("java.lang.NullPointerException",
     "Cannot invoke \"String.length()\" because \"payeeName\" is null"),
    ("java.util.concurrent.RejectedExecutionException",
     "Task rejected from ThreadPoolExecutor[Running, pool size = 32]"),
    ("io.lettuce.core.RedisCommandTimeoutException",
     "Command timed out after 3 second(s)"),
    ("com.austinbank.auth.TokenValidationException",
     "JWT signature does not match locally computed signature"),
]


def rid():
    return "".join(random.choices("0123456789abcdef", k=16))


def acct():
    if random.random() < 0.04:
        return random.choice(PERSONA_ACCOUNTS)
    return random.randrange(1, MAX_ACCOUNT_ID + 1)


# ---------------------------------------------------------------------------
# Line formats. Each returns one raw log line (occasionally multi-line).
# Signature: fn(ts, stressed, srate) -> str
# ---------------------------------------------------------------------------
# Which services plausibly emit which message themes. Keeps the logger name
# consistent with the body -- a batch job should not log "failed login".
SVC_THEMES = {
    "auth-service": "auth", "session-service": "auth", "onboarding-api": "auth",
    "transfer-service": "txn", "payment-gateway": "txn", "ledger-api": "txn",
    "account-service": "acct", "payee-service": "acct", "card-service": "acct",
    "fraud-scoring": "risk", "statement-batch": "batch",
    "notification-service": "notify",
}


def log4j(ts, stressed, srate):
    svc = random.choice(SERVICES)
    theme = SVC_THEMES[svc]
    lvl = random.choices(
        ["INFO", "DEBUG", "WARN", "ERROR"],
        weights=[0.55, 0.25, 0.14, 0.06] if not stressed else [0.25, 0.10, 0.40, 0.25])[0]
    thread = f"http-nio-8080-exec-{random.randrange(1, 33)}"
    pkg = PACKAGES[svc]
    stamp = ts.strftime("%Y-%m-%d %H:%M:%S,") + f"{ts.microsecond // 1000:03d}"
    a = acct()
    cip = client_ip(srate)

    generic_err = [
        f"Downstream call failed endpoint=core-banking status=503 accountId={a} retries=3",
        f"Unable to acquire lock on accountId={a} after 5000ms",
    ]
    generic_warn = [
        f"Slow query detected duration={random.randrange(1200, 9000)}ms sql=\"{random.choice(SQL)}\"",
        f"Connection pool usage at {random.randrange(82, 100)}% active={random.randrange(41, 50)} idle={random.randrange(0, 4)}",
        f"Retry {random.randrange(1, 4)}/3 for accountId={a} operation={random.choice(['balanceInquiry', 'postingSubmit', 'payeeLookup'])}",
    ]
    themed = {
        "auth": {
            "ERROR": [f"Token validation failed clientIp={cip} accountId={a} reason=SIGNATURE_MISMATCH",
                      f"MFA challenge could not be delivered accountId={a} channel=sms"],
            "WARN": [f"Repeated failed login user={random.choice(USERS)} clientIp={cip} attempts={random.randrange(3, 9)}",
                     f"Rate limit approaching client={random.choice(USERS)} clientIp={cip} used={random.randrange(880, 999)}/1000",
                     f"Geo-velocity check flagged accountId={a} clientIp={cip} deltaKm={random.randrange(900, 9000)}"],
            "DEBUG": [f"Session token issued sub={random.choice(USERS)} clientIp={cip} exp={random.randrange(900, 3600)}s"],
            "INFO": [f"Authenticated user={random.choice(USERS)} accountId={a} clientIp={cip} mfa={random.choice(['totp', 'sms', 'none'])}",
                     f"Device registered accountId={a} deviceId={rid()[:12]} clientIp={cip}",
                     f"KYC step completed accountId={a} step={random.choice(['id_upload', 'selfie', 'address', 'review'])}"],
        },
        "txn": {
            "ERROR": [f"Failed to post transaction for accountId={a} ref=TRX-{rid()[:10].upper()} cause=LEDGER_TIMEOUT",
                      f"Wire submission rejected accountId={a} swift=CHASUS33 reason=INVALID_BENEFICIARY"],
            "WARN": [f"Settlement window closing with {random.randrange(1, 40)} pending postings",
                     f"Duplicate transfer reference detected accountId={a} ref=TRX-{rid()[:10].upper()}"],
            "DEBUG": [f"Executing {random.choice(SQL)} params=[{a}]"],
            "INFO": [f"Transfer accepted accountId={a} amount={round(random.uniform(5, 25000), 2)} currency=USD ref=TRX-{rid()[:10].upper()}",
                     f"Posting committed accountId={a} journalId=JRN-{random.randrange(10**7, 10**8)}"],
        },
        "acct": {
            "ERROR": [f"Card activation failed accountId={a} last4={random.randrange(1000, 9999)} reason=ISSUER_DECLINE",
                      f"Account projection rebuild failed accountId={a}"],
            "WARN": [f"Unauthorized account access attempt accountId={a} clientIp={cip}",
                     f"Deprecated API version requested path=/api/v1/balance clientIp={cip}"],
            "DEBUG": [f"Cache {random.choice(['hit', 'miss'])} key=acct:{a}:balance ttl={random.randrange(30, 300)}s",
                      f"Serialized response bytes={random.randrange(180, 24000)} correlationId={rid()}"],
            "INFO": [f"Balance inquiry accountId={a} clientIp={cip} elapsed={random.randrange(4, 180)}ms",
                     f"Payee added accountId={a} payeeId=PY-{rid()[:8].upper()} clientIp={cip}"],
        },
        "risk": {
            "ERROR": [f"Model inference failed accountId={a} model=xgb-v4 cause=FEATURE_TIMEOUT"],
            "WARN": [f"Risk rule threshold exceeded accountId={a} rule=VELOCITY_24H hits={random.randrange(4, 40)}",
                     f"Feature store staleness {random.randrange(20, 400)}min model=xgb-v4"],
            "DEBUG": [f"Feature vector assembled accountId={a} dims={random.randrange(40, 220)}"],
            "INFO": [f"Fraud score computed accountId={a} score={round(random.uniform(0, 1), 3)} model=xgb-v4",
                     f"Case opened accountId={a} caseId=CS-{random.randrange(10**5, 10**6)} priority={random.choice(['low', 'medium', 'high'])}"],
        },
        "batch": {
            "ERROR": [f"Batch job failed job=statementRun chunk={random.randrange(1, 400)} cause=IO_ERROR"],
            "WARN": [f"Batch running behind schedule job=statementRun lagMin={random.randrange(15, 400)}",
                     f"Bulk export requested rows={random.randrange(500, 9000)} clientIp={cip}"],
            "DEBUG": [f"Chunk committed job=statementRun size={random.randrange(100, 5000)}"],
            "INFO": [f"Statement generated accountId={a} period={ts.strftime('%Y-%m')} pages={random.randrange(1, 9)}",
                     f"Batch completed job=statementRun records={random.randrange(1000, 90000)} durationMs={random.randrange(9000, 900000)}"],
        },
        "notify": {
            "ERROR": [f"SMS dispatch failed accountId={a} provider=twilio status={random.choice([421, 500, 503])}"],
            "WARN": [f"Notification retry {random.randrange(1, 4)}/3 accountId={a} channel={random.choice(['sms', 'email', 'push'])}"],
            "DEBUG": [f"Template rendered id=tpl_{random.randrange(10, 99)} accountId={a}"],
            "INFO": [f"Notification delivered accountId={a} channel={random.choice(['sms', 'email', 'push'])} latencyMs={random.randrange(30, 4000)}"],
        },
    }
    pool = themed[theme].get(lvl, [])
    if lvl == "ERROR":
        pool = pool + generic_err
    elif lvl == "WARN":
        pool = pool + generic_warn
    body = random.choice(pool)
    return f"{stamp} {lvl:5s} [{thread}] {pkg} - {body}"


def nginx(ts, stressed, srate):
    cip = client_ip(srate)
    bad = cip == SUSPICIOUS_IP
    if bad:
        status = random.choices([401, 403, 404, 429, 200, 500],
                                weights=[0.34, 0.20, 0.22, 0.14, 0.08, 0.02])[0]
        path = random.choice(RECON_PATHS)
        if "%d" in path:
            path = path % acct()
        agent = random.choice(BAD_AGENTS)
        user = random.choice(TARGET_USERS + ["-"])
        rt = random.uniform(0.001, 0.09)
        size = random.randrange(0, 900)
        method = random.choices(["GET", "POST", "HEAD"], weights=[0.5, 0.42, 0.08])[0]
    else:
        status = random.choices(
            [200, 201, 204, 301, 400, 401, 403, 404, 429, 500, 502, 503],
            weights=([0.62, 0.06, 0.04, 0.01, 0.03, 0.05, 0.02, 0.05, 0.02, 0.05, 0.03, 0.02]
                     if not stressed else
                     [0.30, 0.02, 0.02, 0.01, 0.04, 0.05, 0.02, 0.04, 0.10, 0.20, 0.12, 0.08]))[0]
        path = f"{random.choice(ENDPOINTS)}?accountId={acct()}"
        agent = random.choice(AGENTS)
        user = random.choice(USERS + ["-", "-", "-"])
        rt = random.uniform(0.002, 8.5)
        size = random.randrange(120, 48000)
        method = random.choice(["GET", "POST", "PUT", "DELETE"])
    return (f'{cip} - {user} [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{method} {path} HTTP/1.1" {status} {size} '
            f'"-" "{agent}" rt={rt:.3f}')


def haproxy(ts, stressed, srate):
    cip = client_ip(srate)
    be = random.choice(["be_auth", "be_accounts", "be_transfers", "be_static"])
    code = random.choices([200, 401, 403, 429, 500, 503],
                          weights=[0.7, 0.08, 0.05, 0.05, 0.07, 0.05]
                          if not stressed else [0.35, 0.1, 0.05, 0.15, 0.2, 0.15])[0]
    return (f"{ts.strftime('%b %e %H:%M:%S')} atx-edge-01 haproxy[{random.randrange(900, 9999)}]: "
            f"{cip}:{random.randrange(30000, 65000)} [{ts.strftime('%d/%b/%Y:%H:%M:%S.')}"
            f"{ts.microsecond // 1000:03d}] fe_https~ {be}/srv{random.randrange(1, 7)} "
            f"{random.randrange(0, 40)}/{random.randrange(0, 900)}/{random.randrange(1, 60)}/"
            f"{random.randrange(1, 4000)}/{random.randrange(5, 5000)} {code} "
            f"{random.randrange(100, 40000)} - - ---- "
            f"{random.randrange(1, 900)}/{random.randrange(1, 400)}/0/0/0 0/0 "
            f'"{random.choice(["GET", "POST"])} {random.choice(ENDPOINTS)} HTTP/2.0"')


def envoy(ts, stressed, srate):
    cip = client_ip(srate)
    code = random.choices([200, 401, 403, 404, 429, 503],
                          weights=[0.68, 0.08, 0.05, 0.07, 0.06, 0.06])[0]
    flags = random.choice(["-", "-", "-", "UF", "UO", "NR", "DC"])
    return (f'[{ts.strftime("%Y-%m-%dT%H:%M:%S.")}{ts.microsecond // 1000:03d}Z] '
            f'"{random.choice(["GET", "POST"])} {random.choice(ENDPOINTS)} HTTP/2" '
            f'{code} {flags} {random.randrange(0, 900)} {random.randrange(100, 30000)} '
            f'{random.randrange(1, 3000)} {random.randrange(1, 2900)} '
            f'"{cip}" "{random.choice(AGENTS)}" "{rid()}" '
            f'"{random.choice(SERVICES)}.svc.cluster.local" "10.42.{random.randrange(1, 4)}.{random.randrange(2, 250)}:8080"')


def waf(ts, stressed, srate):
    """ModSecurity-style block. Weighted heavily toward the suspicious host."""
    cip = SUSPICIOUS_IP if random.random() < max(srate * 6, 0.35) else client_ip(srate)
    rule, msg = random.choice([
        (942100, "SQL Injection Attack Detected via libinjection"),
        (930110, "Path Traversal Attack (/../)"),
        (913100, "Found User-Agent associated with security scanner"),
        (949110, "Inbound Anomaly Score Exceeded"),
        (920350, "Host header is a numeric IP address"),
        (941100, "XSS Attack Detected via libinjection"),
    ])
    payload = random.choice(SQLI_PROBES) if rule in (942100, 949110) else \
        random.choice(RECON_PATHS).replace("%d", str(acct()))
    return (f'{ts.strftime("%Y/%m/%d %H:%M:%S")} [error] {random.randrange(100, 9999)}#0: '
            f'*{random.randrange(1000, 999999)} ModSecurity: Access denied with code 403 '
            f'(phase 2). Matched "Operator `Rx` with parameter" against variable `ARGS` '
            f'[id "{rule}"] [msg "{msg}"] [severity "CRITICAL"] [data "{payload}"], '
            f'client: {cip}, server: api.austinbank.example, '
            f'request: "{random.choice(["GET", "POST"])} {random.choice(ENDPOINTS)} HTTP/1.1"')


def iis(ts, stressed, srate):
    cip = client_ip(srate)
    return (f"{ts.strftime('%Y-%m-%d %H:%M:%S')} 10.42.3.22 "
            f"{random.choice(['GET', 'POST'])} {random.choice(ENDPOINTS)} "
            f"accountId={acct()} 443 - {cip} "
            f"{random.choice(AGENTS).replace(' ', '+')} - "
            f"{random.choice([200, 302, 401, 403, 404, 500])} 0 0 "
            f"{random.randrange(2, 4000)}")


def cef(ts, stressed, srate):
    cip = client_ip(srate)
    bad = cip == SUSPICIOUS_IP
    sig, name, sev = random.choice([
        ("100", "Successful Login", 2), ("101", "Failed Login", 5),
        ("205", "Excessive Authentication Failures", 8),
        ("310", "Privilege Escalation Attempt", 9),
        ("402", "Anomalous Data Access Volume", 7),
        ("150", "Password Reset Requested", 3),
    ]) if not bad else random.choice([
        ("101", "Failed Login", 5), ("205", "Excessive Authentication Failures", 8),
        ("310", "Privilege Escalation Attempt", 9),
        ("402", "Anomalous Data Access Volume", 7),
    ])
    return (f"{ts.strftime('%b %e %H:%M:%S')} atx-siem CEF:0|AustinBank|CoreAuth|4.2|"
            f"{sig}|{name}|{sev}|src={cip} suser={random.choice(TARGET_USERS if bad else USERS)} "
            f"dst=10.42.1.17 dpt=443 cs1Label=accountId cs1={acct()} "
            f"cs2Label=sessionId cs2={rid()} outcome={'failure' if bad else 'success'}")


def syslog(ts, stressed, srate):
    host = random.choice(HOSTS)
    proc = random.choice(["sshd", "systemd", "kernel", "cron", "sudo", "audit",
                          "sssd", "chronyd"])
    pid = random.randrange(200, 32000)
    cip = client_ip(srate)
    body = random.choice([
        f"Accepted publickey for {random.choice(USERS)} from {cip} port {random.randrange(30000, 65000)} ssh2",
        f"Failed password for invalid user {random.choice(TARGET_USERS)} from {cip} port {random.randrange(30000, 65000)} ssh2",
        f"Failed password for {random.choice(USERS)} from {cip} port {random.randrange(30000, 65000)} ssh2",
        f"Started Session {random.randrange(1000, 99999)} of user {random.choice(USERS)}.",
        f"pam_unix(sudo:session): session opened for user root by {random.choice(USERS)}(uid={random.randrange(1000, 1050)})",
        f"Out of memory: Killed process {pid} (java) total-vm:{random.randrange(8, 24)}G",
        f"Disconnected from authenticating user {random.choice(TARGET_USERS)} {cip} port {random.randrange(30000, 65000)} [preauth]",
        f"error: maximum authentication attempts exceeded for {random.choice(TARGET_USERS)} from {cip} port {random.randrange(30000, 65000)} ssh2 [preauth]",
    ])
    return f"{ts.strftime('%b %e %H:%M:%S')} {host} {proc}[{pid}]: {body}"


def hikari(ts, stressed, srate):
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
    active = random.randrange(44, 51) if stressed else random.randrange(2, 30)
    return (f"{stamp} | {random.choice(HOSTS)} | HikariPool-1 | "
            f"pool stats: total={50} active={active} idle={50 - active} "
            f"waiting={random.randrange(8, 60) if stressed else 0}")


def gc(ts, stressed, srate):
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}+0000"
    before = random.randrange(2400, 7800)
    after = before - random.randrange(300, 2100)
    pause = round(random.uniform(0.9, 48.0) * (3 if stressed else 1), 3)
    kind = random.choices(["Pause Young (Normal) (G1 Evacuation Pause)",
                           "Pause Young (Concurrent Start) (G1 Humongous Allocation)",
                           "Pause Full (System.gc())"],
                          weights=[0.82, 0.14, 0.04])[0]
    return (f"[{stamp}] GC(#{random.randrange(100, 9999)}) {kind} "
            f"{before}M->{after}M(8192M) {pause}ms")


def kafka(ts, stressed, srate):
    stamp = ts.strftime("%Y-%m-%d %H:%M:%S,") + f"{ts.microsecond // 1000:03d}"
    topic = random.choice(["txn-events", "auth-events", "ledger-postings",
                           "fraud-alerts", "notification-outbound",
                           "session-events", "audit-trail"])
    lag = random.randrange(4000, 250000) if stressed else random.randrange(0, 900)
    return (f"{stamp} INFO  [Consumer clientId=consumer-{random.randrange(1, 9)}] "
            f"group=fraud-pipeline topic={topic} partition={random.randrange(0, 12)} "
            f"offset={random.randrange(10**6, 10**9)} lag={lag}")


def postgres(ts, stressed, srate):
    stamp = ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d} UTC"
    pid = random.randrange(1000, 99999)
    lvl, body = random.choice([
        ("LOG", f"duration: {random.uniform(1000, 22000):.3f} ms  statement: {random.choice(SQL)}"),
        ("LOG", f"checkpoint complete: wrote {random.randrange(200, 9000)} buffers "
                f"({random.uniform(0.1, 9.9):.1f}%); sync files={random.randrange(2, 60)}"),
        ("WARNING", f"there is already a transaction in progress"),
        ("ERROR", f"deadlock detected  DETAIL: Process {pid} waits for ShareLock on "
                  f"transaction {random.randrange(10**6, 10**8)}"),
        ("ERROR", f"canceling statement due to statement timeout"),
        ("FATAL", f"remaining connection slots are reserved for non-replication "
                  f"superuser connections"),
    ] if not stressed else [
        ("ERROR", "canceling statement due to statement timeout"),
        ("FATAL", "remaining connection slots are reserved for non-replication "
                  "superuser connections"),
        ("LOG", f"duration: {random.uniform(9000, 45000):.3f} ms  statement: {random.choice(SQL)}"),
    ])
    return (f"{stamp} [{pid}] {random.choice(['ledger', 'core', 'authdb'])}@"
            f"{random.choice(['ledger_api', 'auth_service'])} {lvl}:  {body}")


def redis(ts, stressed, srate):
    return (f"{random.randrange(100, 9999)}:M {ts.strftime('%d %b %Y %H:%M:%S.')}"
            f"{ts.microsecond // 1000:03d} * " + random.choice([
                f"Background saving terminated with success",
                f"DB saved on disk",
                f"{random.randrange(1, 900)} changes in {random.randrange(60, 900)} seconds. Saving...",
                f"Client id={random.randrange(1000, 99999)} addr={client_ip(srate)}:"
                f"{random.randrange(30000, 65000)} scheduled to be closed ASAP for "
                f"overcoming of output buffer limits",
                f"Evicted {random.randrange(10, 9000)} keys due to maxmemory policy allkeys-lru",
            ]))


def jsonish(ts, stressed, srate):
    a = acct()
    cip = client_ip(srate)
    return ('{"ts":"%s","svc":"%s","lvl":"%s","msg":"%s","accountId":%d,'
            '"clientIp":"%s","traceId":"%s","durationMs":%d,"status":%d}' % (
                ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
                random.choice(SERVICES),
                random.choices(["info", "warn", "error"],
                               weights=[0.7, 0.2, 0.1] if not stressed else [0.3, 0.4, 0.3])[0],
                random.choice(["request completed", "payee validated",
                               "otp dispatched", "session refreshed",
                               "risk rule evaluated", "webhook delivered",
                               "document uploaded", "limit check passed",
                               "device fingerprint recorded"]),
                a, cip, rid(), random.randrange(2, 9000),
                random.choice([200, 200, 200, 201, 400, 401, 403, 500])))


def stacktrace(ts, stressed, srate):
    exc, detail = random.choice(TRACE_EXCEPTIONS)
    svc = random.choice(SERVICES)
    stamp = ts.strftime("%Y-%m-%d %H:%M:%S,") + f"{ts.microsecond // 1000:03d}"
    frames = [
        f"\tat {PACKAGES[svc]}.handle({PACKAGES[svc].split('.')[-1]}.java:{random.randrange(40, 400)})",
        f"\tat com.zaxxer.hikari.pool.HikariPool.getConnection(HikariPool.java:{random.randrange(100, 220)})",
        f"\tat org.springframework.jdbc.datasource.DataSourceUtils.fetchConnection(DataSourceUtils.java:{random.randrange(120, 180)})",
        f"\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:{random.randrange(100, 200)})",
        f"\tat java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144)",
        "\tat java.base/java.lang.Thread.run(Thread.java:1583)",
    ]
    tail = ""
    if random.random() < 0.3:
        tail = (f"\nCaused by: {random.choice(TRACE_EXCEPTIONS)[0]}: connection reset"
                f"\n\t... {random.randrange(12, 60)} common frames omitted")
    return (f"{stamp} ERROR [http-nio-8080-exec-{random.randrange(1, 33)}] "
            f"{PACKAGES[svc]} - Unhandled exception accountId={acct()} "
            f"clientIp={client_ip(srate)}\n"
            f"{exc}: {detail}\n" + "\n".join(frames[:random.randrange(3, 7)]) + tail)


# ---------------------------------------------------------------------------
# Attack campaign lines — emitted in bursts, always from SUSPICIOUS_IP.
# ---------------------------------------------------------------------------
def campaign_line(ts, phase):
    """phase: 'recon' | 'stuffing' | 'enumeration' | 'exfil'"""
    cip = SUSPICIOUS_IP
    stamp4j = ts.strftime("%Y-%m-%d %H:%M:%S,") + f"{ts.microsecond // 1000:03d}"
    nstamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

    if phase == "recon":
        path = random.choice(RECON_PATHS)
        if "%d" in path:
            path = path % acct()
        return (f'{cip} - - [{nstamp}] "GET {path} HTTP/1.1" '
                f'{random.choice([403, 404, 404, 401])} {random.randrange(0, 600)} '
                f'"-" "{random.choice(BAD_AGENTS)}" rt={random.uniform(0.001, 0.05):.3f}')
    if phase == "stuffing":
        user = random.choice(TARGET_USERS)
        return random.choice([
            f'{cip} - - [{nstamp}] "POST /api/v2/auth/login HTTP/1.1" 401 '
            f'{random.randrange(60, 200)} "-" "{random.choice(BAD_AGENTS)}" '
            f'rt={random.uniform(0.01, 0.12):.3f}',
            f"{stamp4j} WARN  [http-nio-8080-exec-{random.randrange(1, 33)}] "
            f"c.a.b.auth.LoginController - Authentication failed user={user} "
            f"clientIp={cip} reason=BAD_CREDENTIALS attempt={random.randrange(1, 80)}",
            f"{ts.strftime('%b %e %H:%M:%S')} atx-siem CEF:0|AustinBank|CoreAuth|4.2|"
            f"205|Excessive Authentication Failures|8|src={cip} suser={user} "
            f"dst=10.42.1.17 dpt=443 cs1Label=accountId cs1={acct()} outcome=failure",
        ])
    if phase == "enumeration":
        a = acct()
        return random.choice([
            f'{cip} - - [{nstamp}] "GET /api/v2/accounts?accountId={a} HTTP/1.1" '
            f'{random.choice([403, 403, 404, 200])} {random.randrange(0, 900)} '
            f'"-" "{random.choice(BAD_AGENTS)}" rt={random.uniform(0.002, 0.06):.3f}',
            f"{stamp4j} WARN  [http-nio-8080-exec-{random.randrange(1, 33)}] "
            f"c.a.b.acct.AccountQueryService - Unauthorized account access attempt "
            f"accountId={a} clientIp={cip} principal={random.choice(TARGET_USERS)}",
            f'{{"ts":"{ts.strftime("%Y-%m-%dT%H:%M:%S.")}{ts.microsecond // 1000:03d}Z",'
            f'"svc":"account-service","lvl":"warn","msg":"forbidden resource",'
            f'"accountId":{a},"clientIp":"{cip}","traceId":"{rid()}",'
            f'"durationMs":{random.randrange(2, 40)},"status":403}}',
        ])
    # exfil
    return random.choice([
        f"{stamp4j} WARN  [http-nio-8080-exec-{random.randrange(1, 33)}] "
        f"c.a.b.batch.StatementJob - Bulk export requested rows={random.randrange(5000, 90000)} "
        f"clientIp={cip} principal={random.choice(TARGET_USERS)} format=csv",
        f'{cip} - {random.choice(TARGET_USERS)} [{nstamp}] '
        f'"GET /api/v1/internal/ledger/export?from=2019-01-01 HTTP/1.1" 200 '
        f'{random.randrange(2_000_000, 90_000_000)} "-" "{random.choice(BAD_AGENTS)}" '
        f'rt={random.uniform(4.0, 60.0):.3f}',
        f"{ts.strftime('%b %e %H:%M:%S')} atx-siem CEF:0|AustinBank|DLP|4.2|402|"
        f"Anomalous Data Access Volume|7|src={cip} suser={random.choice(TARGET_USERS)} "
        f"dst=10.42.1.17 cs1Label=bytes cs1={random.randrange(10**7, 10**9)} outcome=success",
    ])


FORMATS = [
    (log4j, 0.26), (nginx, 0.20), (jsonish, 0.10), (syslog, 0.08),
    (haproxy, 0.06), (envoy, 0.05), (kafka, 0.05), (postgres, 0.05),
    (cef, 0.04), (hikari, 0.03), (gc, 0.03), (iis, 0.02), (redis, 0.01),
    (waf, 0.01), (stacktrace, 0.01),
]
FNS = [f for f, _ in FORMATS]
WTS = [w for _, w in FORMATS]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=500_000)
    ap.add_argument("--days", type=float, default=30.0)
    ap.add_argument("--out", default="app_logs.parquet")
    ap.add_argument("--incidents", type=int, default=4,
                    help="number of pool-saturation bursts to weave in")
    ap.add_argument("--campaigns", type=int, default=4,
                    help="number of attack bursts from the suspicious IP")
    ap.add_argument("--suspicious-rate", type=float, default=0.03,
                    help="baseline share of client-IP lines using %s "
                         "(0 disables the malicious actor entirely)" % SUSPICIOUS_IP)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    random.seed(args.seed)
    _build_client_pool(random.Random(args.seed))

    srate = max(0.0, min(1.0, args.suspicious_rate))
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    s, e = start.timestamp(), end.timestamp()

    # incident windows: ~35 minutes of degradation each
    incidents = []
    for _ in range(args.incidents):
        t0 = random.uniform(s, e - 3600)
        incidents.append((t0, t0 + random.uniform(900, 2700)))

    # attack campaigns: longer, and biased toward off-hours so the time-of-day
    # signal is learnable by an ML job
    campaigns = []
    if srate > 0 and args.campaigns > 0:
        phases = ["recon", "stuffing", "enumeration", "exfil"]
        for i in range(args.campaigns):
            for _ in range(40):
                t0 = random.uniform(s, e - 7200)
                hour = datetime.fromtimestamp(t0, tz=timezone.utc).hour
                if hour <= 11 or hour >= 4:      # 22:00-06:00 CT-ish
                    break
            phase = phases[i % len(phases)]
            campaigns.append((t0, t0 + random.uniform(1800, 5400), phase))

    def stressed_at(epoch):
        return any(a <= epoch <= b for a, b in incidents)

    def campaign_at(epoch):
        for a, b, phase in campaigns:
            if a <= epoch <= b:
                return phase
        return None

    # Weight timestamps toward business hours, then sort so the file reads
    # like an actual log rather than shuffled noise.
    stamps = []
    while len(stamps) < args.rows:
        t = random.uniform(s, e)
        hour = datetime.fromtimestamp(t, tz=timezone.utc).hour
        keep = 1.0 if 13 <= hour <= 23 else 0.35      # ~business hours in CT
        if stressed_at(t) or campaign_at(t):
            keep = 1.0                                # bursts survive sampling
        if random.random() < keep:
            stamps.append(t)
    stamps.sort()

    messages = []
    susp_lines = 0
    for t in stamps:
        ts = datetime.fromtimestamp(t, tz=timezone.utc)
        hot = stressed_at(t)
        phase = campaign_at(t)

        if phase and random.random() < 0.55:
            line = campaign_line(ts, phase)
        else:
            fn = random.choices(FNS, weights=WTS)[0]
            if hot and random.random() < 0.22:
                fn = random.choice([stacktrace, hikari, log4j, postgres])
            line = fn(ts, hot, srate)

        if SUSPICIOUS_IP in line:
            susp_lines += 1
        messages.append(line)

    table = pa.table({"message": pa.array(messages, type=pa.string())})
    pq.write_table(table, args.out, compression="snappy", row_group_size=100_000)

    size = os.path.getsize(args.out) / 1e6
    raw = sum(len(m) for m in messages) / 1e6
    print(f"wrote {args.out}: {table.num_rows:,} rows x 1 col "
          f"({size:.1f} MB on disk, {raw:.1f} MB raw text)")
    print(f"  window     : {start:%Y-%m-%d %H:%M} .. {end:%Y-%m-%d %H:%M} UTC")
    print(f"  client IPs : 10.30.255.0 .. 10.50.255.0 ({_POOL_SIZE} distinct)")
    print(f"  incidents  : {args.incidents} pool-saturation bursts")
    print(f"  campaigns  : {len(campaigns)} attack bursts from {SUSPICIOUS_IP}")
    print(f"  suspicious : {susp_lines:,} lines "
          f"({susp_lines / max(1, len(messages)) * 100:.2f}% of total)")


if __name__ == "__main__":
    main()
