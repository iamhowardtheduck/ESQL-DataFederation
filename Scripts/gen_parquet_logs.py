#!/usr/bin/env python3
"""
gen_parquet_logs.py — unstructured application logs, one column: `message`.

Emits a single-column Parquet file whose only field is a raw log line, mixing
the formats a real banking platform actually produces: Log4j/Logback, nginx
combined access logs, syslog, HikariCP pool warnings, JVM GC lines, Kafka
consumer output, embedded JSON, and multi-line Java stack traces.

Nothing is pre-parsed. The point is to force DISSECT / GROK / regex work at
query time, which is the interesting part of querying object storage from ES|QL.

Account IDs (1..35000) and the Fraud-Workshop persona accounts appear inside
the text, so parsed logs can be correlated back to the transaction data.

A recurring incident is woven in: roughly once a week the connection pool
saturates and produces a burst of WARN/ERROR/stack traces across services --
useful for log rate analysis and change point detection.

Usage:
    python3 gen_parquet_logs.py
    python3 gen_parquet_logs.py --rows 2000000 --days 30 --out app_logs.parquet
    python3 gen_parquet_logs.py --incidents 0        # clean baseline, no bursts
"""
import argparse
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

HOSTS = ["ip-10-42-1-17", "ip-10-42-1-38", "ip-10-42-2-9", "ip-10-42-2-51",
         "ip-10-42-3-22", "atx-app-01", "atx-app-02", "atx-batch-01"]
SERVICES = ["auth-service", "transfer-service", "account-service",
            "payment-gateway", "ledger-api", "notification-service",
            "fraud-scoring", "statement-batch"]
PACKAGES = {
    "auth-service": "c.a.b.auth.LoginController",
    "transfer-service": "c.a.b.txn.WireTransferService",
    "account-service": "c.a.b.acct.AccountQueryService",
    "payment-gateway": "c.a.b.pay.GatewayDispatcher",
    "ledger-api": "c.a.b.ledger.PostingEngine",
    "notification-service": "c.a.b.notify.SmsDispatcher",
    "fraud-scoring": "c.a.b.risk.ScoreEvaluator",
    "statement-batch": "c.a.b.batch.StatementJob",
}
ENDPOINTS = ["/api/v2/accounts", "/api/v2/transfers", "/api/v2/auth/login",
             "/api/v2/auth/refresh", "/api/v2/statements", "/api/v2/payees",
             "/api/v1/balance", "/health", "/actuator/prometheus"]
AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.5",
    "AustinBank/4.12.1 (iPhone; iOS 18.2)",
    "AustinBank/4.11.0 (Android 15; Pixel 8)",
    "python-requests/2.32.3",
    "curl/8.7.1",
]
USERS = ["jmartinez", "bkozlov", "hsidorov", "cma", "vmoeller", "dlu", "dtian",
         "ycho", "apatel", "rwilliams", "svc_ledger", "svc_batch", "tnguyen"]
SQL = [
    "SELECT * FROM accounts WHERE account_id = ?",
    "SELECT balance, status FROM ledger_positions WHERE account_id = ? FOR UPDATE",
    "UPDATE ledger_positions SET balance = balance - ? WHERE account_id = ?",
    "INSERT INTO transaction_journal (account_id, amount, event_type) VALUES (?, ?, ?)",
    "SELECT COUNT(*) FROM wire_queue WHERE status = 'PENDING'",
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
]


def rid():
    return "".join(random.choices("0123456789abcdef", k=16))


def acct():
    if random.random() < 0.04:
        return random.choice(PERSONA_ACCOUNTS)
    return random.randrange(1, MAX_ACCOUNT_ID + 1)


def ip():
    return (f"{random.choice([10, 172, 192, 203, 66, 74])}."
            f"{random.randrange(0, 255)}.{random.randrange(0, 255)}."
            f"{random.randrange(1, 254)}")


# ---------------------------------------------------------------------------
# Line formats. Each returns one raw log line (occasionally multi-line).
# ---------------------------------------------------------------------------
def log4j(ts, stressed):
    svc = random.choice(SERVICES)
    lvl = random.choices(
        ["INFO", "DEBUG", "WARN", "ERROR"],
        weights=[0.55, 0.25, 0.14, 0.06] if not stressed else [0.25, 0.10, 0.40, 0.25])[0]
    thread = f"http-nio-8080-exec-{random.randrange(1, 33)}"
    pkg = PACKAGES[svc]
    stamp = ts.strftime("%Y-%m-%d %H:%M:%S,") + f"{ts.microsecond // 1000:03d}"
    a = acct()

    if lvl == "ERROR":
        body = random.choice([
            f"Failed to post transaction for accountId={a} ref=TRX-{rid()[:10].upper()} cause=LEDGER_TIMEOUT",
            f"Downstream call failed endpoint=core-banking status=503 accountId={a} retries=3",
            f"Unable to acquire lock on accountId={a} after 5000ms",
            f"Wire submission rejected accountId={a} swift=CHASUS33 reason=INVALID_BENEFICIARY",
        ])
    elif lvl == "WARN":
        body = random.choice([
            f"Slow query detected duration={random.randrange(1200, 9000)}ms sql=\"{random.choice(SQL)}\"",
            f"Retry {random.randrange(1, 4)}/3 for accountId={a} operation=balanceInquiry",
            f"Connection pool usage at {random.randrange(82, 100)}% active={random.randrange(41, 50)} idle={random.randrange(0, 4)}",
            f"Rate limit approaching client={random.choice(USERS)} used={random.randrange(880, 999)}/1000",
        ])
    elif lvl == "DEBUG":
        body = random.choice([
            f"Cache {random.choice(['hit', 'miss'])} key=acct:{a}:balance ttl={random.randrange(30, 300)}s",
            f"Executing {random.choice(SQL)} params=[{a}]",
            f"Serialized response bytes={random.randrange(180, 24000)} correlationId={rid()}",
        ])
    else:
        body = random.choice([
            f"Authenticated user={random.choice(USERS)} accountId={a} mfa={random.choice(['totp', 'sms', 'none'])}",
            f"Transfer accepted accountId={a} amount={round(random.uniform(5, 25000), 2)} currency=USD ref=TRX-{rid()[:10].upper()}",
            f"Balance inquiry accountId={a} elapsed={random.randrange(4, 180)}ms",
            f"Statement generated accountId={a} period={ts.strftime('%Y-%m')} pages={random.randrange(1, 9)}",
            f"Fraud score computed accountId={a} score={round(random.uniform(0, 1), 3)} model=xgb-v4",
        ])
    return f"{stamp} {lvl:5s} [{thread}] {pkg} - {body}"


def nginx(ts, stressed):
    status = random.choices(
        [200, 201, 204, 301, 400, 401, 403, 404, 429, 500, 502, 503],
        weights=([0.62, 0.06, 0.04, 0.01, 0.03, 0.05, 0.02, 0.05, 0.02, 0.05, 0.03, 0.02]
                 if not stressed else
                 [0.30, 0.02, 0.02, 0.01, 0.04, 0.05, 0.02, 0.04, 0.10, 0.20, 0.12, 0.08]))[0]
    return (f'{ip()} - {random.choice(USERS + ["-", "-", "-"])} '
            f'[{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{random.choice(["GET", "POST", "PUT", "DELETE"])} '
            f'{random.choice(ENDPOINTS)}?accountId={acct()} HTTP/1.1" '
            f'{status} {random.randrange(120, 48000)} '
            f'"-" "{random.choice(AGENTS)}" rt={random.uniform(0.002, 8.5):.3f}')


def syslog(ts, stressed):
    host = random.choice(HOSTS)
    proc = random.choice(["sshd", "systemd", "kernel", "cron", "sudo", "audit"])
    pid = random.randrange(200, 32000)
    body = random.choice([
        f"Accepted publickey for {random.choice(USERS)} from {ip()} port {random.randrange(30000, 65000)} ssh2",
        f"Failed password for invalid user {random.choice(['admin', 'oracle', 'test', 'postgres'])} from {ip()} port {random.randrange(30000, 65000)} ssh2",
        f"Started Session {random.randrange(1000, 99999)} of user {random.choice(USERS)}.",
        f"pam_unix(sudo:session): session opened for user root by {random.choice(USERS)}(uid={random.randrange(1000, 1050)})",
        f"Out of memory: Killed process {pid} (java) total-vm:{random.randrange(8, 24)}G",
    ])
    return f"{ts.strftime('%b %e %H:%M:%S')} {host} {proc}[{pid}]: {body}"


def hikari(ts, stressed):
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
    active = random.randrange(44, 51) if stressed else random.randrange(2, 30)
    return (f"{stamp} | {random.choice(HOSTS)} | HikariPool-1 | "
            f"pool stats: total={50} active={active} idle={50 - active} "
            f"waiting={random.randrange(8, 60) if stressed else 0}")


def gc(ts, stressed):
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}+0000"
    before = random.randrange(2400, 7800)
    after = before - random.randrange(300, 2100)
    pause = round(random.uniform(0.9, 48.0) * (3 if stressed else 1), 3)
    return (f"[{stamp}] GC(#{random.randrange(100, 9999)}) Pause Young "
            f"(Normal) (G1 Evacuation Pause) {before}M->{after}M(8192M) {pause}ms")


def kafka(ts, stressed):
    stamp = ts.strftime("%Y-%m-%d %H:%M:%S,") + f"{ts.microsecond // 1000:03d}"
    topic = random.choice(["txn-events", "auth-events", "ledger-postings",
                           "fraud-alerts", "notification-outbound"])
    lag = random.randrange(4000, 250000) if stressed else random.randrange(0, 900)
    return (f"{stamp} INFO  [Consumer clientId=consumer-{random.randrange(1, 9)}] "
            f"group=fraud-pipeline topic={topic} partition={random.randrange(0, 12)} "
            f"offset={random.randrange(10**6, 10**9)} lag={lag}")


def jsonish(ts, stressed):
    a = acct()
    return ('{"ts":"%s","svc":"%s","lvl":"%s","msg":"%s","accountId":%d,'
            '"traceId":"%s","durationMs":%d}' % (
                ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
                random.choice(SERVICES),
                random.choices(["info", "warn", "error"],
                               weights=[0.7, 0.2, 0.1] if not stressed else [0.3, 0.4, 0.3])[0],
                random.choice(["request completed", "payee validated",
                               "otp dispatched", "session refreshed",
                               "risk rule evaluated", "webhook delivered"]),
                a, rid(), random.randrange(2, 9000)))


def stacktrace(ts, stressed):
    exc, detail = random.choice(TRACE_EXCEPTIONS)
    svc = random.choice(SERVICES)
    stamp = ts.strftime("%Y-%m-%d %H:%M:%S,") + f"{ts.microsecond // 1000:03d}"
    frames = [
        f"\tat {PACKAGES[svc]}.handle({PACKAGES[svc].split('.')[-1]}.java:{random.randrange(40, 400)})",
        f"\tat com.zaxxer.hikari.pool.HikariPool.getConnection(HikariPool.java:{random.randrange(100, 220)})",
        f"\tat org.springframework.jdbc.datasource.DataSourceUtils.fetchConnection(DataSourceUtils.java:{random.randrange(120, 180)})",
        f"\tat java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144)",
        "\tat java.base/java.lang.Thread.run(Thread.java:1583)",
    ]
    return (f"{stamp} ERROR [http-nio-8080-exec-{random.randrange(1, 33)}] "
            f"{PACKAGES[svc]} - Unhandled exception accountId={acct()}\n"
            f"{exc}: {detail}\n" + "\n".join(frames[:random.randrange(3, 6)]))


FORMATS = [
    (log4j, 0.40), (nginx, 0.24), (jsonish, 0.11), (syslog, 0.09),
    (kafka, 0.06), (hikari, 0.04), (gc, 0.04), (stacktrace, 0.02),
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
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    random.seed(args.seed)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    s, e = start.timestamp(), end.timestamp()

    # incident windows: ~35 minutes of degradation each
    incidents = []
    for _ in range(args.incidents):
        t0 = random.uniform(s, e - 3600)
        incidents.append((t0, t0 + random.uniform(900, 2700)))

    def stressed_at(epoch):
        return any(a <= epoch <= b for a, b in incidents)

    # Weight timestamps toward business hours, then sort so the file reads
    # like an actual log rather than shuffled noise.
    stamps = []
    while len(stamps) < args.rows:
        t = random.uniform(s, e)
        hour = datetime.fromtimestamp(t, tz=timezone.utc).hour
        keep = 1.0 if 13 <= hour <= 23 else 0.35      # ~business hours in CT
        if stressed_at(t):
            keep = 1.0                                # bursts survive sampling
        if random.random() < keep:
            stamps.append(t)
    stamps.sort()

    messages = []
    for t in stamps:
        ts = datetime.fromtimestamp(t, tz=timezone.utc)
        hot = stressed_at(t)
        fn = random.choices(FNS, weights=WTS)[0]
        if hot and random.random() < 0.22:
            fn = random.choice([stacktrace, hikari, log4j])
        messages.append(fn(ts, hot))

    table = pa.table({"message": pa.array(messages, type=pa.string())})
    pq.write_table(table, args.out, compression="snappy", row_group_size=100_000)

    import os
    size = os.path.getsize(args.out) / 1e6
    raw = sum(len(m) for m in messages) / 1e6
    print(f"wrote {args.out}: {table.num_rows:,} rows x 1 col "
          f"({size:.1f} MB on disk, {raw:.1f} MB raw text)")
    print(f"  window: {start:%Y-%m-%d %H:%M} .. {end:%Y-%m-%d %H:%M} UTC")
    print(f"  incidents: {args.incidents} pool-saturation bursts")


if __name__ == "__main__":
    main()
