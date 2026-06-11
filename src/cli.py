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
from typing import Any, Dict, List, Optional, Tuple

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
        collection_profile_id: str = None,
    ):
        self.server_url = server_url
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.artifacts = artifacts
        self.request_signer = request_signer
        self.config = config or {}
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="forensic_collect_")
        self.collection_profile_id = collection_profile_id
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

            # Stage 2: Compute hashes for integrity verification
            logger.info("[Stage 2/3] Computing file hashes...")
            hashed_files = self._compute_hashes(collected_files)
            if not hashed_files:
                logger.error("No collected files passed upload-readiness checks.")
                return False
            logger.info(f"[Stage 2/3] Hashed {len(hashed_files)} files")

            # Stage 3: Upload to server
            logger.info("[Stage 3/3] Uploading to server...")
            success = self._upload(hashed_files)
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

    def _collect(self) -> List[Tuple[str, str, Dict[str, Any]]]:
        """Stage 1: Collect artifacts to output directory."""
        collected = []

        # Platform-aware collector selection
        if sys.platform == 'darwin':
            # macOS local live collection
            from collectors.artifact_collector import LocalSystemCollector
            collector = LocalSystemCollector(
                self.output_dir, os_type='macos', target_root='/'
            )
            logger.info(f"  Platform: macOS local ({collector.get_collection_mode()})")
            return self._collect_with_local_collector(collector)

        elif sys.platform.startswith('linux'):
            # Linux local live collection
            from collectors.artifact_collector import LocalSystemCollector
            collector = LocalSystemCollector(
                self.output_dir, os_type='linux', target_root='/'
            )
            logger.info(f"  Platform: Linux local ({collector.get_collection_mode()})")
            return self._collect_with_local_collector(collector)

        else:
            # Windows (existing behavior)
            from collectors.artifact_collector import ArtifactCollector
            collector = ArtifactCollector(output_dir=self.output_dir)

            for i, artifact_type in enumerate(self.artifacts, 1):
                if self._cancelled:
                    break
                logger.info(f"  [{i}/{len(self.artifacts)}] Collecting: {artifact_type}")
                try:
                    file_count = 0
                    for item in collector.collect(artifact_type) or []:
                        normalized = self._normalize_collected_item(item, artifact_type)
                        if normalized:
                            collected.append(normalized)
                            file_count += 1
                    if file_count:
                        logger.info(f"    -> {file_count} files")
                    else:
                        logger.info(f"    -> 0 files (none found)")
                except Exception as e:
                    logger.warning(f"    -> Failed: {e}")

            return collected

    def _collect_with_local_collector(self, collector) -> List[Tuple[str, str, Dict[str, Any]]]:
        """Collect artifacts using LocalSystemCollector (macOS/Linux)."""
        collected = []

        for i, artifact_type in enumerate(self.artifacts, 1):
            if self._cancelled:
                break
            logger.info(f"  [{i}/{len(self.artifacts)}] Collecting: {artifact_type}")
            file_count = 0
            try:
                for item in collector.collect(artifact_type) or []:
                    normalized = self._normalize_collected_item(item, artifact_type)
                    if not normalized:
                        metadata = item[1] if isinstance(item, tuple) and len(item) > 1 and isinstance(item[1], dict) else {}
                        error_msg = metadata.get('error', 'Unknown')
                        if metadata.get('status') not in ('not_found', 'skipped'):
                            logger.warning(f"    -> {artifact_type}: {error_msg}")
                        continue
                    collected.append(normalized)
                    file_count += 1
                if file_count > 0:
                    logger.info(f"    -> {file_count} files")
                else:
                    logger.info(f"    -> 0 files (none found)")
            except Exception as e:
                logger.warning(f"    -> Failed: {e}")

        # Report permission errors
        if hasattr(collector, 'permission_error_count') and collector.permission_error_count > 0:
            logger.warning(
                f"  {collector.permission_error_count} files skipped "
                f"(permission denied). Run with sudo for full access."
            )

        return collected

    def _normalize_collected_item(
        self,
        item: Any,
        artifact_type: str,
    ) -> Optional[Tuple[str, str, Dict[str, Any]]]:
        """Normalize collector outputs to (path, artifact_type, metadata)."""
        metadata: Dict[str, Any] = {}
        upload_artifact_type = artifact_type
        filepath = item

        if isinstance(item, tuple):
            if len(item) >= 2 and isinstance(item[1], dict):
                filepath = item[0]
                metadata = dict(item[1] or {})
                upload_artifact_type = metadata.get("upload_artifact_type") or artifact_type
            else:
                filepath = item[0] if item else None
                if len(item) >= 2 and isinstance(item[1], str):
                    upload_artifact_type = item[1]
                if len(item) >= 3 and isinstance(item[2], dict):
                    metadata = dict(item[2] or {})

        status = metadata.get("status")
        if status in ("error", "not_found", "skipped", "not_implemented"):
            return None

        if not filepath or not isinstance(filepath, (str, os.PathLike)):
            logger.warning(f"    -> {artifact_type}: invalid collector output path")
            return None

        filepath = os.fspath(filepath)
        if not os.path.isfile(filepath):
            logger.warning(f"    -> {artifact_type}: collected path is not a readable file: {filepath}")
            return None

        metadata.setdefault("original_path", filepath)
        metadata.setdefault("artifact_type", upload_artifact_type)
        return filepath, upload_artifact_type, metadata

    def _unpack_upload_entry(
        self,
        entry: Any,
    ) -> Tuple[str, str, Dict[str, Any]]:
        if isinstance(entry, tuple):
            filepath = entry[0]
            artifact_type = entry[1] if len(entry) >= 2 else "unknown"
            metadata = entry[2] if len(entry) >= 3 and isinstance(entry[2], dict) else {}
            return os.fspath(filepath), artifact_type, dict(metadata or {})
        return os.fspath(entry), "unknown", {}

    def _compute_hashes(self, files: List[Tuple[str, str, Dict[str, Any]]]) -> List[Tuple[str, str, Dict[str, Any]]]:
        """Stage 2: Compute SHA-256 hashes for integrity verification.

        Note: Upload security is handled by DirectUploader during Stage 3.
        """
        from core.encryptor import FileHashCalculator

        calculator = FileHashCalculator()
        verified = []

        for i, entry in enumerate(files, 1):
            if self._cancelled:
                break
            filepath, artifact_type, metadata = self._unpack_upload_entry(entry)
            if i % 50 == 0 or i == len(files):
                logger.info(f"  Hashing [{i}/{len(files)}]")
            try:
                hash_result = calculator.calculate_file_hash(filepath)
                with open(filepath, "rb") as readable:
                    readable.read(1)
                stat_result = os.stat(filepath)
                if hash_result.file_size <= 0:
                    raise ValueError("empty file")
                metadata["hash_sha256"] = hash_result.sha256_hash
                metadata["sha256"] = hash_result.sha256_hash
                metadata["original_hash"] = hash_result.sha256_hash
                metadata["original_size"] = hash_result.file_size
                metadata["upload_hash_sha256"] = hash_result.sha256_hash
                metadata["upload_hash_size"] = hash_result.file_size
                metadata["upload_hash_mtime_ns"] = getattr(
                    stat_result,
                    "st_mtime_ns",
                    int(stat_result.st_mtime * 1_000_000_000),
                )
                metadata["upload_hash_path"] = os.path.abspath(filepath)
                verified.append((filepath, artifact_type, metadata))
            except Exception as e:
                logger.warning(f"  Hash failed: {os.path.basename(filepath)}: {e}")

        return verified

    def _upload(self, files: List[Tuple[str, str, Dict[str, Any]]]) -> bool:
        """Stage 3: Upload files via presigned URLs."""
        from core.uploader import DirectUploader

        if not files:
            logger.error("No files to upload.")
            return False

        uploader = DirectUploader(
            server_url=self.server_url,
            session_id=self.session_id,
            collection_token=self.collection_token,
            case_id=self.case_id,
            config=self.config,
            request_signer=self.request_signer,
            profile_id=self.collection_profile_id,
        )

        success_count = 0
        fail_count = 0

        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading

        lock = threading.Lock()
        completed = [0]

        def _upload_one(entry):
            filepath, artifact_type, metadata = self._unpack_upload_entry(entry)
            upload_metadata = dict(metadata or {})
            upload_metadata.setdefault("source", "headless_collector")
            upload_metadata.setdefault("original_path", filepath)
            result = uploader.upload_file(
                file_path=filepath,
                artifact_type=artifact_type,
                metadata=upload_metadata,
            )
            with lock:
                completed[0] += 1
                if completed[0] % 10 == 0 or completed[0] == len(files):
                    logger.info(f"  Uploading [{completed[0]}/{len(files)}]")
            return filepath, result

        max_workers = min(uploader.upload_workers, len(files))
        logger.info(f"  Upload concurrency: {max_workers} worker(s)")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for entry in files:
                if self._cancelled:
                    break
                futures.append(executor.submit(_upload_one, entry))

            for future in as_completed(futures):
                if self._cancelled:
                    break
                try:
                    filepath, result = future.result()
                    if result.success:
                        success_count += 1
                    else:
                        fail_count += 1
                        logger.warning(f"  Upload failed: {os.path.basename(filepath)}: {result.error}")
                except Exception as e:
                    fail_count += 1
                    logger.warning(f"  Upload exception: {e}")

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
        # Pass server-provided hkdf_info if available (backward compatible)
        hkdf_info = getattr(result, 'hkdf_info', None)
        hkdf_info_bytes = hkdf_info.encode('utf-8') if hkdf_info else None
        request_signer = RequestSigner(hw_id, result.challenge_salt or "", result.signing_key or "", hkdf_info=hkdf_info_bytes)
    except Exception as e:
        logger.warning(f"Request signer init failed: {e}")

    # Step 3: Apply server profile and determine artifacts to collect
    from collectors.artifact_collector import (
        ARTIFACT_TYPES, ANDROID_ARTIFACT_TYPES, IOS_ARTIFACT_TYPES,
        LINUX_ARTIFACT_TYPES, MACOS_ARTIFACT_TYPES,
    )
    from collectors.base_mft_collector import ARTIFACT_MFT_FILTERS
    from core.collection_profile import (
        apply_collection_profile_to_mobile_ffs,
        apply_collection_profile_to_registry,
    )

    profile_artifacts = set()
    profile_targets = getattr(result, 'collection_profile_targets', None) or []
    for registry in (
        ARTIFACT_TYPES, ARTIFACT_MFT_FILTERS,
        ANDROID_ARTIFACT_TYPES, IOS_ARTIFACT_TYPES,
        LINUX_ARTIFACT_TYPES, MACOS_ARTIFACT_TYPES,
    ):
        profile_artifacts.update(apply_collection_profile_to_registry(profile_targets, registry))
    apply_collection_profile_to_mobile_ffs(profile_targets)

    if args.artifacts:
        artifacts = [a.strip() for a in args.artifacts.split(",") if a.strip()]
    else:
        artifacts = result.allowed_artifacts or []
        if "all" in artifacts:
            artifacts = sorted(profile_artifacts) if profile_artifacts else list(ARTIFACT_TYPES.keys())

    artifacts = [artifact for artifact in artifacts if artifact in ARTIFACT_TYPES]

    if not artifacts:
        logger.error("No artifacts specified. Use --artifacts or check server configuration.")
        return 1

    # Step 4: Run collection
    collector = HeadlessCollector(
        server_url=server_url,  # [SECURITY] Always use user-provided URL, never trust server response
        session_id=result.session_id,
        collection_token=result.collection_token,
        case_id=result.case_id,
        artifacts=artifacts,
        request_signer=request_signer,
        config=config,
        output_dir=args.output_dir,
        collection_profile_id=getattr(result, 'collection_profile_id', None),
    )

    success = collector.run()
    return 0 if success else 1
