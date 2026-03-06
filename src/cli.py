"""
CLI / Headless Mode for Digital Forensics Collector

Enables collection on Linux servers and other environments without GUI.

Usage:
    python main.py --headless --token TOKEN --server https://server.example.com
    python main.py --headless --token TOKEN --server URL --artifacts prefetch,eventlog
"""
import logging
import os
import sys
import tempfile
import threading
import time
from typing import List, Optional

logger = logging.getLogger(__name__)


def _setup_logging():
    """Configure console logging for headless mode."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def _check_admin_headless():
    """Check admin/root privileges in headless mode (warning only)."""
    from utils.privilege import is_admin

    if not is_admin():
        logger.warning("Running without root/admin privileges. Some collection features may be limited.")
        if sys.platform != 'win32':
            logger.warning("For full functionality, run with: sudo ./run.sh --headless ...")


class HeadlessCollector:
    """
    Three-stage collection pipeline without Qt dependencies.

    Stage 1: Collect artifacts to temp directory
    Stage 2: Encrypt collected files
    Stage 3: Upload to server
    """

    def __init__(
        self,
        server_url: str,
        session_id: str,
        collection_token: str,
        case_id: str,
        artifacts: List[str],
        request_signer=None,
        config: dict = None,
        output_dir: str = None,
    ):
        self.server_url = server_url
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.artifacts = artifacts
        self.request_signer = request_signer
        self.config = config or {}
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="forensic_collect_")
        self._cancelled = False

    def run(self) -> bool:
        """Execute the full collection pipeline. Returns True on success."""
        logger.info("=" * 60)
        logger.info("Digital Forensics Collector — Headless Mode")
        logger.info("=" * 60)
        logger.info(f"Server: {self.server_url}")
        logger.info(f"Case ID: {self.case_id}")
        logger.info(f"Session: {self.session_id}")
        logger.info(f"Artifacts: {', '.join(self.artifacts)}")
        logger.info(f"Output dir: {self.output_dir}")
        logger.info("-" * 60)

        try:
            # Stage 1: Collect
            logger.info("[Stage 1/3] Collecting artifacts...")
            collected_files = self._collect()
            if not collected_files:
                logger.error("No artifacts collected.")
                return False
            logger.info(f"[Stage 1/3] Collected {len(collected_files)} files")

            # Stage 2: Encrypt
            logger.info("[Stage 2/3] Encrypting files...")
            encrypted_files = self._encrypt(collected_files)
            logger.info(f"[Stage 2/3] Encrypted {len(encrypted_files)} files")

            # Stage 3: Upload
            logger.info("[Stage 3/3] Uploading to server...")
            success = self._upload(encrypted_files)
            if success:
                logger.info("[Stage 3/3] Upload complete!")
                logger.info("=" * 60)
                logger.info("Collection finished successfully.")
                logger.info("=" * 60)
            return success

        except KeyboardInterrupt:
            logger.warning("Collection cancelled by user (Ctrl+C)")
            self._cancelled = True
            return False
        except Exception as e:
            logger.error(f"Collection failed: {e}", exc_info=True)
            return False

    def _collect(self) -> List[str]:
        """Stage 1: Collect artifacts to output directory."""
        from collectors.artifact_collector import ArtifactCollector

        collected = []
        collector = ArtifactCollector(output_dir=self.output_dir)

        for i, artifact_type in enumerate(self.artifacts, 1):
            if self._cancelled:
                break
            logger.info(f"  [{i}/{len(self.artifacts)}] Collecting: {artifact_type}")
            try:
                files = collector.collect(artifact_type)
                if files:
                    collected.extend(files)
                    logger.info(f"    -> {len(files)} files")
                else:
                    logger.info(f"    -> 0 files (none found)")
            except Exception as e:
                logger.warning(f"    -> Failed: {e}")

        return collected

    def _encrypt(self, files: List[str]) -> List[str]:
        """Stage 2: Encrypt collected files."""
        from core.file_encryptor import FileEncryptor

        encryptor = FileEncryptor()
        encrypted = []

        for i, filepath in enumerate(files, 1):
            if self._cancelled:
                break
            if i % 50 == 0 or i == len(files):
                logger.info(f"  Encrypting [{i}/{len(files)}]")
            try:
                enc_path = encryptor.encrypt_file(filepath)
                if enc_path:
                    encrypted.append(enc_path)
            except Exception as e:
                logger.warning(f"  Encrypt failed: {os.path.basename(filepath)}: {e}")

        return encrypted

    def _upload(self, files: List[str]) -> bool:
        """Stage 3: Upload encrypted files to server."""
        import requests

        upload_url = f"{self.server_url}/api/v1/collector/raw-files/upload"
        success_count = 0
        fail_count = 0

        for i, filepath in enumerate(files, 1):
            if self._cancelled:
                break

            if i % 10 == 0 or i == len(files):
                logger.info(f"  Uploading [{i}/{len(files)}]")

            try:
                headers = {
                    "X-Collection-Token": self.collection_token,
                    "X-Session-ID": self.session_id,
                }

                # Add HMAC signature if signer available
                if self.request_signer:
                    sig_headers = self.request_signer.sign_request(
                        "POST",
                        "/api/v1/collector/raw-files/upload",
                        body=None,
                        collection_token=self.collection_token,
                    )
                    headers.update(sig_headers)

                with open(filepath, 'rb') as f:
                    resp = requests.post(
                        upload_url,
                        headers=headers,
                        files={"file": (os.path.basename(filepath), f)},
                        data={
                            "session_id": self.session_id,
                            "case_id": self.case_id,
                        },
                        timeout=120,
                        verify=True,
                    )

                if resp.status_code in (200, 201):
                    success_count += 1
                else:
                    fail_count += 1
                    logger.warning(f"  Upload failed ({resp.status_code}): {os.path.basename(filepath)}")

            except Exception as e:
                fail_count += 1
                logger.warning(f"  Upload error: {os.path.basename(filepath)}: {e}")

        logger.info(f"  Upload summary: {success_count} succeeded, {fail_count} failed")
        return fail_count == 0


def run_headless(args, config: dict) -> int:
    """
    Entry point for headless/CLI mode.

    Args:
        args: Parsed argparse namespace
        config: Application config dict

    Returns:
        Exit code (0 = success, 1 = failure)
    """
    _setup_logging()
    _check_admin_headless()

    server_url = args.server or config.get('server_url', '')
    if not server_url:
        logger.error("Server URL is required. Use --server URL")
        return 1

    # Step 1: Authenticate
    logger.info("Authenticating with server...")
    from core.token_validator import TokenValidator
    validator = TokenValidator(server_url)
    result = validator.validate(args.token, allow_revalidation=True)

    if not result.valid:
        logger.error(f"Authentication failed: {result.error}")
        return 1

    logger.info(f"Authenticated. Case: {result.case_id}, Session: {result.session_id}")

    # Step 2: Initialize request signer
    request_signer = None
    try:
        from utils.hardware_id import get_hardware_id
        from core.request_signer import RequestSigner
        hw_id = get_hardware_id()
        request_signer = RequestSigner(hw_id, result.challenge_salt or "", result.signing_key or "")
    except Exception as e:
        logger.warning(f"Request signer init failed: {e}")

    # Step 3: Determine artifacts to collect
    if args.artifacts:
        artifacts = [a.strip() for a in args.artifacts.split(",")]
    else:
        artifacts = result.allowed_artifacts or []

    if not artifacts:
        logger.error("No artifacts specified. Use --artifacts or check server configuration.")
        return 1

    # Step 4: Run collection
    collector = HeadlessCollector(
        server_url=(server_url if ("localhost" in (result.server_url or "") or "127.0.0.1" in (result.server_url or "")) else (result.server_url or server_url)),
        session_id=result.session_id,
        collection_token=result.collection_token,
        case_id=result.case_id,
        artifacts=artifacts,
        request_signer=request_signer,
        config=config,
        output_dir=args.output_dir,
    )

    success = collector.run()
    return 0 if success else 1
