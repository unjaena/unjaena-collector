# -*- coding: utf-8 -*-
"""
Multi-Device Collector

Coordinator for collecting artifacts from multiple devices in parallel.

Features:
    - ThreadPoolExecutor-based parallel collection
    - Per-device progress tracking
    - Continue on error
    - UI integration via Qt signals
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum, auto

from PyQt6.QtCore import QObject, pyqtSignal

from .device_manager import UnifiedDeviceInfo, DeviceType, DeviceStatus

logger = logging.getLogger(__name__)


# =============================================================================
# Enums & Data Classes
# =============================================================================

class TaskStatus(Enum):
    """Collection task status"""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass
class CollectionTask:
    """Per-device collection task information"""
    device: UnifiedDeviceInfo
    artifacts: List[str]
    status: TaskStatus = TaskStatus.PENDING
    progress: float = 0.0
    current_artifact: str = ""
    collected_files: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None


@dataclass
class CollectionResult:
    """Collection result"""
    device_id: str
    success: bool
    collected_count: int
    error_count: int
    files: List[str]
    errors: List[str]
    duration_seconds: float


# =============================================================================
# Error Handler
# =============================================================================

class CollectionErrorHandler:
    """
    Error handler during collection

    Decides whether to continue based on error type.
    """

    # Critical errors (stop device collection)
    CRITICAL_ERRORS = (
        PermissionError,
        ConnectionRefusedError,
        ConnectionResetError,
    )

    def __init__(self, on_error: Optional[Callable[[str, str, str], None]] = None):
        self.on_error = on_error
        self._device_errors: Dict[str, List[str]] = {}

    def handle_error(
        self,
        device_id: str,
        artifact_type: str,
        error: Exception
    ) -> bool:
        """
        Handle error

        Args:
            device_id: Device ID
            artifact_type: Artifact type
            error: Exception that occurred

        Returns:
            True: continue, False: stop device collection
        """
        error_msg = str(error)

        if device_id not in self._device_errors:
            self._device_errors[device_id] = []

        self._device_errors[device_id].append(f"{artifact_type}: {error_msg}")

        logger.warning(f"[{device_id}] Error collecting {artifact_type}: {error_msg}")

        if self.on_error:
            self.on_error(device_id, artifact_type, error_msg)

        # Check for critical error
        if isinstance(error, self.CRITICAL_ERRORS):
            logger.error(f"[{device_id}] Critical error - stopping device collection")
            return False

        return True  # Continue

    def get_errors(self, device_id: str) -> List[str]:
        """Get per-device error list"""
        return self._device_errors.get(device_id, [])

    def get_all_errors(self) -> Dict[str, List[str]]:
        """Get all errors"""
        return self._device_errors.copy()


# =============================================================================
# Multi-Device Collector
# =============================================================================

class MultiDeviceCollector(QObject):
    """
    Multi-device parallel collector

    Collects artifacts from multiple devices simultaneously.

    Signals:
        collection_started: Collection started
        collection_completed: Collection completed
        device_started(device_id): Device collection started
        device_progress(device_id, progress, artifact): Device progress
        device_completed(device_id, success, message): Device collection completed
        artifact_collected(device_id, file_path): Artifact collected
        error_occurred(device_id, artifact, error): Error occurred

    Usage:
        collector = MultiDeviceCollector(max_workers=3)

        collector.device_progress.connect(on_progress)
        collector.device_completed.connect(on_completed)

        devices = [device1, device2, device3]
        artifacts = {'device1_id': ['registry', 'prefetch'], ...}

        collector.start_collection(devices, artifacts)
    """

    # Signals
    collection_started = pyqtSignal()
    collection_completed = pyqtSignal(list)  # List[CollectionResult]
    device_started = pyqtSignal(str)  # device_id
    device_progress = pyqtSignal(str, float, str)  # device_id, progress, artifact
    device_completed = pyqtSignal(str, bool, str)  # device_id, success, message
    artifact_collected = pyqtSignal(str, str)  # device_id, file_path
    error_occurred = pyqtSignal(str, str, str)  # device_id, artifact, error

    def __init__(self, max_workers: int = 3, parent=None):
        super().__init__(parent)

        self.max_workers = max_workers
        self._executor: Optional[ThreadPoolExecutor] = None
        self._tasks: Dict[str, CollectionTask] = {}
        self._results: List[CollectionResult] = []
        self._cancelled = threading.Event()
        self._error_handler = CollectionErrorHandler(self._on_error)
        self._output_dir: Optional[str] = None

    def set_output_dir(self, output_dir: str):
        """Set output directory"""
        self._output_dir = output_dir

    def start_collection(
        self,
        devices: List[UnifiedDeviceInfo],
        artifacts_per_device: Dict[str, List[str]]
    ):
        """
        Start parallel collection

        Args:
            devices: List of devices to collect from
            artifacts_per_device: Mapping of artifact types per device
        """
        if not devices:
            logger.warning("No devices to collect from")
            return

        self._cancelled.clear()
        self._tasks.clear()
        self._results.clear()

        self.collection_started.emit()
        logger.info(f"Starting collection from {len(devices)} devices (max workers: {self.max_workers})")

        # Create tasks
        for device in devices:
            artifacts = artifacts_per_device.get(device.device_id, [])
            if not artifacts:
                logger.warning(f"No artifacts specified for {device.device_id}")
                continue

            task = CollectionTask(
                device=device,
                artifacts=artifacts,
            )
            self._tasks[device.device_id] = task

        # Execute in parallel with ThreadPoolExecutor
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        futures = {}

        for device_id, task in self._tasks.items():
            future = self._executor.submit(self._collect_from_device, task)
            futures[future] = device_id

        # Collect results (in separate thread)
        threading.Thread(
            target=self._wait_for_completion,
            args=(futures,),
            daemon=True
        ).start()

    def _wait_for_completion(self, futures: dict):
        """Wait for all tasks to complete"""
        import time

        for future in as_completed(futures):
            device_id = futures[future]
            task = self._tasks.get(device_id)

            try:
                result = future.result()
                self._results.append(result)

            except Exception as e:
                logger.error(f"[{device_id}] Collection failed: {e}")
                if task:
                    task.status = TaskStatus.FAILED
                    task.error_message = str(e)

                self._results.append(CollectionResult(
                    device_id=device_id,
                    success=False,
                    collected_count=0,
                    error_count=1,
                    files=[],
                    errors=[str(e)],
                    duration_seconds=0,
                ))

                self.device_completed.emit(device_id, False, str(e))

        # All tasks completed
        self._executor.shutdown(wait=False)
        logger.info(f"Collection completed: {len(self._results)} devices processed")
        self.collection_completed.emit(self._results)

    def _collect_from_device(self, task: CollectionTask) -> CollectionResult:
        """
        Collect from individual device (executed in worker thread)

        Args:
            task: Collection task information

        Returns:
            Collection result
        """
        import time

        device = task.device
        device_id = device.device_id
        start_time = time.time()

        task.status = TaskStatus.RUNNING
        task.start_time = start_time
        self.device_started.emit(device_id)

        logger.info(f"[{device_id}] Starting collection: {task.artifacts}")

        collector = self._get_collector_for_device(device)
        if not collector:
            raise RuntimeError(f"No collector available for {device.device_type.name}")

        collected_files = []
        errors = []
        total_artifacts = len(task.artifacts)

        for i, artifact_type in enumerate(task.artifacts):
            if self._cancelled.is_set():
                task.status = TaskStatus.CANCELLED
                raise RuntimeError("Collection cancelled")

            task.current_artifact = artifact_type
            task.progress = i / total_artifacts
            self.device_progress.emit(device_id, task.progress, artifact_type)

            try:
                for file_path, metadata in collector.collect(artifact_type):
                    collected_files.append(file_path)
                    task.collected_files.append(file_path)
                    self.artifact_collected.emit(device_id, file_path)

            except Exception as e:
                errors.append(f"{artifact_type}: {e}")
                should_continue = self._error_handler.handle_error(
                    device_id, artifact_type, e
                )
                if not should_continue:
                    break

        # Complete
        end_time = time.time()
        task.end_time = end_time
        task.progress = 1.0

        success = len(errors) == 0 or len(collected_files) > 0
        task.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED

        # Cleanup collector
        if hasattr(collector, 'close'):
            collector.close()

        result = CollectionResult(
            device_id=device_id,
            success=success,
            collected_count=len(collected_files),
            error_count=len(errors),
            files=collected_files,
            errors=errors,
            duration_seconds=end_time - start_time,
        )

        message = f"Collected {len(collected_files)} files"
        if errors:
            message += f" ({len(errors)} errors)"

        self.device_completed.emit(device_id, success, message)
        logger.info(f"[{device_id}] Completed: {message}")

        return result

    def _get_collector_for_device(self, device: UnifiedDeviceInfo):
        """
        Return appropriate collector for device type

        Args:
            device: Device information

        Returns:
            Appropriate collector instance
        """
        output_dir = self._output_dir or './collected'

        if device.device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            # Use LocalMFTCollector (BitLocker auto-detection + directory fallback)
            from collectors.artifact_collector import LocalMFTCollector, BASE_MFT_AVAILABLE
            if BASE_MFT_AVAILABLE:
                volume = device.metadata.get('volume', 'C')
                collector = LocalMFTCollector(output_dir, volume=volume)
                logger.info(f"Using LocalMFTCollector (mode: {collector.get_collection_mode()})")
                return collector
            else:
                # Use legacy ArtifactCollector if BaseMFTCollector not available
                from collectors.artifact_collector import ArtifactCollector
                logger.info("Using legacy ArtifactCollector (BaseMFTCollector not available)")
                return ArtifactCollector(output_dir)

        elif device.device_type in (
            DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE,
            DeviceType.VMDK_IMAGE, DeviceType.VHD_IMAGE,
            DeviceType.VHDX_IMAGE, DeviceType.QCOW2_IMAGE,
            DeviceType.VDI_IMAGE,
        ):
            from collectors.e01_artifact_collector import E01ArtifactCollector
            file_path = device.metadata.get('file_path')
            if not file_path:
                raise ValueError("No file_path in device metadata")
            collector = E01ArtifactCollector(file_path, output_dir)
            # Auto-select first NTFS partition
            partitions = collector.list_partitions()
            for p in partitions:
                if getattr(p, 'filesystem', '').upper() == 'NTFS':
                    collector.select_partition(p.index)
                    break
            return collector

        elif device.device_type == DeviceType.ANDROID_DEVICE:
            from collectors.android_collector import AndroidCollector
            collector = AndroidCollector(output_dir)
            serial = device.metadata.get('serial')
            if serial:
                collector.connect(serial)
            return collector

        elif device.device_type == DeviceType.IOS_BACKUP:
            from collectors.ios_collector import iOSCollector
            collector = iOSCollector(output_dir)
            backup_path = device.metadata.get('path')
            if backup_path:
                collector.select_backup(backup_path)
            return collector

        elif device.device_type == DeviceType.IOS_DEVICE:
            # [2026-01-30] iOS USB direct connection support
            from collectors.ios_collector import iOSDeviceConnector, PYMOBILEDEVICE3_AVAILABLE
            if not PYMOBILEDEVICE3_AVAILABLE:
                raise RuntimeError("pymobiledevice3 is not installed. pip install pymobiledevice3")
            udid = device.metadata.get('udid') or device.metadata.get('serial')
            collector = iOSDeviceConnector(output_dir, udid=udid)
            logger.info(f"Using iOSDeviceConnector for USB direct connection (udid: {udid})")
            return collector

        else:
            raise ValueError(f"Unknown device type: {device.device_type}")

    def _on_error(self, device_id: str, artifact: str, error: str):
        """Error callback"""
        self.error_occurred.emit(device_id, artifact, error)

    def cancel(self):
        """Cancel collection"""
        logger.info("Cancelling collection...")
        self._cancelled.set()

        for task in self._tasks.values():
            if task.status == TaskStatus.RUNNING:
                task.status = TaskStatus.CANCELLED

        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

    def get_task(self, device_id: str) -> Optional[CollectionTask]:
        """Get per-device task status"""
        return self._tasks.get(device_id)

    def get_all_tasks(self) -> Dict[str, CollectionTask]:
        """Get all task status"""
        return self._tasks.copy()

    def get_results(self) -> List[CollectionResult]:
        """Get collection results"""
        return self._results.copy()

    @property
    def is_running(self) -> bool:
        """Check if collection is in progress"""
        return any(
            task.status == TaskStatus.RUNNING
            for task in self._tasks.values()
        )

    @property
    def total_collected(self) -> int:
        """Total number of collected files"""
        return sum(len(task.collected_files) for task in self._tasks.values())
