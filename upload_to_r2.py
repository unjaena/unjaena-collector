#!/usr/bin/env python3
"""
Upload collector EXE to Cloudflare R2.

Usage:
    # With environment variables:
    export CLOUDFLARE_ACCOUNT_ID=your_account_id
    export CLOUDFLARE_R2_ACCESS_KEY=your_access_key
    export CLOUDFLARE_R2_SECRET_KEY=your_secret_key
    python upload_to_r2.py

    # Or with arguments:
    python upload_to_r2.py --account-id YOUR_ID --access-key KEY --secret-key SECRET

    # On RunPod (credentials from .env):
    cd /workspace/AI-DF/migration && source .env
    python /workspace/AI-DF/collector/upload_to_r2.py
"""
import argparse
import hashlib
import os
import sys
from pathlib import Path

import boto3
from botocore.config import Config


def get_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Upload collector EXE to Cloudflare R2")
    parser.add_argument("--account-id", default=os.getenv("CLOUDFLARE_ACCOUNT_ID"))
    parser.add_argument("--access-key", default=os.getenv("CLOUDFLARE_R2_ACCESS_KEY"))
    parser.add_argument("--secret-key", default=os.getenv("CLOUDFLARE_R2_SECRET_KEY"))
    parser.add_argument("--bucket", default=os.getenv("CLOUDFLARE_R2_BUCKET", "forensic-evidence-storage"))
    parser.add_argument("--r2-key", default=os.getenv(
        "COLLECTOR_R2_KEY", "collector/IntelligenceCollector-v2.1.0-20260305.exe"
    ))
    parser.add_argument("--exe-path", default=str(Path(__file__).parent / "dist" / "IntelligenceCollector.exe"))
    args = parser.parse_args()

    if not all([args.account_id, args.access_key, args.secret_key]):
        print("[ERROR] R2 credentials required. Set environment variables or use --account-id/--access-key/--secret-key")
        sys.exit(1)

    exe_path = Path(args.exe_path)
    if not exe_path.exists():
        print(f"[ERROR] EXE not found: {exe_path}")
        sys.exit(1)

    size_mb = exe_path.stat().st_size / (1024 * 1024)
    print(f"[UPLOAD] File: {exe_path}")
    print(f"[UPLOAD] Size: {size_mb:.1f} MB")
    print(f"[UPLOAD] Target: s3://{args.bucket}/{args.r2_key}")

    # Calculate SHA-256
    print("[UPLOAD] Calculating SHA-256...")
    sha256 = get_sha256(exe_path)
    print(f"[UPLOAD] SHA-256: {sha256}")

    # Create R2 client
    endpoint_url = f"https://{args.account_id}.r2.cloudflarestorage.com"
    client = boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key,
        config=Config(
            signature_version="s3v4",
            retries={"max_attempts": 3},
        ),
    )

    # Multipart upload for large files (>100MB)
    from boto3.s3.transfer import TransferConfig
    transfer_config = TransferConfig(
        multipart_threshold=100 * 1024 * 1024,  # 100MB
        multipart_chunksize=50 * 1024 * 1024,   # 50MB per part
        max_concurrency=4,
    )

    print("[UPLOAD] Starting multipart upload to R2...")

    # Progress callback
    uploaded = [0]
    total = exe_path.stat().st_size

    def progress(bytes_transferred):
        uploaded[0] += bytes_transferred
        pct = uploaded[0] / total * 100
        print(f"\r[UPLOAD] Progress: {pct:.1f}% ({uploaded[0] / 1024 / 1024:.0f}/{total / 1024 / 1024:.0f} MB)", end="", flush=True)

    client.upload_file(
        str(exe_path),
        args.bucket,
        args.r2_key,
        ExtraArgs={
            "ContentType": "application/octet-stream",
            "Metadata": {
                "version": "2.1.0",
                "build_date": "2026-03-05",
                "sha256": sha256,
                "platform": "windows-x64",
            },
        },
        Config=transfer_config,
        Callback=progress,
    )

    print(f"\n[SUCCESS] Uploaded to R2: {args.r2_key}")
    print(f"[SUCCESS] SHA-256: {sha256}")
    print(f"\n[INFO] Set this in your RunPod .env:")
    print(f"  COLLECTOR_R2_KEY={args.r2_key}")


if __name__ == "__main__":
    main()
