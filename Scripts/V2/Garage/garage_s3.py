#!/usr/bin/env python3
"""
garage_s3.py — shared S3 sink for the V2 generators, targeting Garage.

Every generator in this directory writes local CSV/Parquet; this module is
the one place that knows how to push those artifacts into the Garage object
store installed by Scripts/install-garage.sh. Defaults line up with that
installer exactly, so on a workshop box `--s3` works with zero configuration:

    endpoint    http://127.0.0.1:9000        (S3_ENDPOINT)
    region      garage                       (S3_REGION — must match s3_region
                                              in /etc/garage.toml)
    bucket      datafederation               (S3_BUCKET)
    access key  minioadmin                   (S3_ACCESS_KEY / AWS_ACCESS_KEY_ID)
    secret key  datafederation_hooray!       (S3_SECRET_KEY / AWS_SECRET_ACCESS_KEY)

Garage specifics vs MinIO/AWS:
  * path-style addressing is required — virtual-hosted style resolves via
    root_domain, which is not set up for workshop hosts, so the client is
    pinned to path-style below;
  * the region is not "us-east-1" unless you changed s3_region; a mismatched
    region fails signature validation with a 400/403;
  * bucket auto-creation only works because install-garage.sh grants the key
    --create-bucket. Without that permission, create the bucket first with
    `garage bucket create <name>` and `garage bucket allow`.

Requires boto3:  pip3 install boto3

IDENTITY_VERSION-style pin so the generators can assert compatibility.
"""
import os
import sys

GARAGE_S3_VERSION = "1"

DEFAULT_ENDPOINT = "http://127.0.0.1:9000"
DEFAULT_REGION = "garage"
DEFAULT_BUCKET = "datafederation"
DEFAULT_ACCESS_KEY = "minioadmin"
DEFAULT_SECRET_KEY = "datafederation_hooray!"


def add_args(ap, default_prefix):
    """Attach the standard --s3* flags to a generator's argparse parser."""
    g = ap.add_argument_group("garage / s3 upload")
    g.add_argument("--s3", action="store_true",
                   help="after writing locally, upload the output to Garage")
    g.add_argument("--s3-endpoint",
                   default=os.environ.get("S3_ENDPOINT", DEFAULT_ENDPOINT))
    g.add_argument("--s3-region",
                   default=os.environ.get("S3_REGION", DEFAULT_REGION))
    g.add_argument("--s3-bucket",
                   default=os.environ.get("S3_BUCKET", DEFAULT_BUCKET))
    g.add_argument("--s3-prefix", default=default_prefix,
                   help="key prefix inside the bucket (default: %(default)s)")


def client(args):
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        sys.exit("--s3 needs boto3: pip3 install boto3")
    access = (os.environ.get("S3_ACCESS_KEY")
              or os.environ.get("AWS_ACCESS_KEY_ID")
              or DEFAULT_ACCESS_KEY)
    secret = (os.environ.get("S3_SECRET_KEY")
              or os.environ.get("AWS_SECRET_ACCESS_KEY")
              or DEFAULT_SECRET_KEY)
    return boto3.client(
        "s3",
        endpoint_url=args.s3_endpoint,
        region_name=args.s3_region,
        aws_access_key_id=access,
        aws_secret_access_key=secret,
        config=Config(
            s3={"addressing_style": "path"},   # required for Garage
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


def ensure_bucket(s3, bucket):
    from botocore.exceptions import ClientError
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError:
        s3.create_bucket(Bucket=bucket)
        print(f"  s3        : created bucket {bucket}")


def _key(prefix, rel):
    prefix = prefix.strip("/")
    rel = rel.replace(os.sep, "/").lstrip("/")
    return f"{prefix}/{rel}" if prefix else rel


def upload_file(s3, bucket, prefix, local, rel=None):
    key = _key(prefix, rel or os.path.basename(local))
    s3.upload_file(local, bucket, key)
    print(f"  s3        : s3://{bucket}/{key} "
          f"({os.path.getsize(local) / 1e6:.1f} MB)")
    return key


def upload_tree(s3, bucket, prefix, local_dir):
    """Upload a directory tree (hive partitions) preserving relative keys."""
    n = 0
    for root, _, files in os.walk(local_dir):
        for f in sorted(files):
            if not f.endswith(".parquet"):
                continue
            path = os.path.join(root, f)
            rel = os.path.join(os.path.basename(local_dir.rstrip(os.sep)),
                               os.path.relpath(path, local_dir))
            upload_file(s3, bucket, prefix, path, rel)
            n += 1
    return n


def push(args, files=(), trees=()):
    """One-call orchestration for the generators: connect, ensure the bucket
    exists, upload every named file and directory tree, print a summary."""
    s3 = client(args)
    ensure_bucket(s3, args.s3_bucket)
    total = 0
    for f in files:
        if f and os.path.exists(f):
            upload_file(s3, args.s3_bucket, args.s3_prefix, f)
            total += 1
    for d in trees:
        if d and os.path.isdir(d):
            total += upload_tree(s3, args.s3_bucket, args.s3_prefix, d)
    print(f"  s3        : {total} object(s) -> {args.s3_endpoint} "
          f"bucket={args.s3_bucket} prefix={args.s3_prefix or '(root)'}")
