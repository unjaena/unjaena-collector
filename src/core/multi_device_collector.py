# -*- coding: utf-8 -*-
"""
Multi-Device Collector

복수 디바이스에서 병렬로 아티팩트를 수집하는 코디네이터.

Features:
    - ThreadPoolExecutor 기반 병렬 수집
    - 디바이스별 진행률 추적
    - 에러 발생 시 계속 진행 (continue on error)
    - Qt 시그널을 통한 UI 연동
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
    """수집 작업 상태"""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass
class CollectionTask:
    """디바이스별 수집 작업 정보"""
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
    """수집 결과"""
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
    수집 중 에러 처리

    에러 유형에 따라 계속 진행 여부를 결정합니다.
    """

    # 치명적 에러 (해당 디바이스 수집 중단)
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
        에러 처리

        Args:
            device_id: 디바이스 ID
            artifact_type: 아티팩트 유형
            error: 발생한 예외

        Returns:
            True: 계속 진행, False: 해당 디바이스 수집 중단
        """
        error_msg = str(error)

        if device_id not in self._device_errors:
            self._device_errors[device_id] = []

        self._device_errors[device_id].append(f"{artifact_type}: {error_msg}")

        logger.warning(f"[{device_id}] Error collecting {artifact_type}: {error_msg}")

        if self.on_error:
            self.on_error(device_id, artifact_type, error_msg)

        # 치명적 에러 확인
        if isinstance(error, self.CRITICAL_ERRORS):
            logger.error(f"[{device_id}] Critical error - stopping device collection")
            return False

        return True  # 계속 진행

    def get_errors(self, device_id: str) -> List[str]:
        """디바이스별 에러 목록"""
        return self._device_errors.get(device_id, [])

    def get_all_errors(self) -> Dict[str, List[str]]:
        """전체 에러 목록"""
        return self._device_errors.copy()


# =============================================================================
# Multi-Device Collector
# =============================================================================

class MultiDeviceCollector(QObject):
    """
    복수 디바이스 병렬 수집기

    여러 디바이스에서 동시에 아티팩트를 수집합니다.

    Signals:
        collection_started: 수집 시작
        collection_completed: 수집 완료
        device_started(device_id): 디바이스 수집 시작
        device_progress(device_id, progress, artifact): 디바이스 진행률
        device_completed(device_id, success, message): 디바이스 수집 완료
        artifact_collected(device_id, file_path): 아티팩트 수집됨
        error_occurred(device_id, artifact, error): 에러 발생

    Usage:
        collector = MultiDeviceCollector(max_workers=3)

        collector.device_progress.connect(on_progress)
        collector.device_completed.connect(on_completed)

        devices = [device1, device2, device3]
        artifacts = {'device1_id': ['registry', 'prefetch'], ...}

        collector.start_collection(devices, artifacts)
    """

    # 시그널
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
        """출력 디렉토리 설정"""
        self._output_dir = output_dir

    def start_collection(
        self,
        devices: List[UnifiedDeviceInfo],
        artifacts_per_device: Dict[str, List[str]]
    ):
        """
        병렬 수집 시작

        Args:
            devices: 수집할 디바이스 목록
            artifacts_per_device: 디바이스별 수집할 아티팩트 유형 매핑
        """
        if not devices:
            logger.warning("No devices to collect from")
            return

        self._cancelled.clear()
        self._tasks.clear()
        self._results.clear()

        self.collection_started.emit()
        logger.info(f"Starting collection from {len(devices)} devices (max workers: {self.max_workers})")

        # 작업 생성
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

        # ThreadPoolExecutor로 병렬 실행
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        futures = {}

        for device_id, task in self._tasks.items():
            future = self._executor.submit(self._collect_from_device, task)
            futures[future] = device_id

        # 결과 수집 (별도 스레드에서)
        threading.Thread(
            target=self._wait_for_completion,
            args=(futures,),
            daemon=True
        ).start()

    def _wait_for_completion(self, futures: dict):
        """모든 작업 완료 대기"""
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

        # 모든 작업 완료
        self._executor.shutdown(wait=False)
        logger.info(f"Collection completed: {len(self._results)} devices processed")
        self.collection_completed.emit(self._results)

    def _collect_from_device(self, task: CollectionTask) -> CollectionResult:
        """
        개별 디바이스에서 수집 (워커 스레드에서 실행)

        Args:
            task: 수집 작업 정보

        Returns:
            수집 결과
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

        # 완료
        end_time = time.time()
        task.end_time = end_time
        task.progress = 1.0

        success = len(errors) == 0 or len(collected_files) > 0
        task.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED

        # 콜렉터 정리
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
        디바이스 유형에 맞는 콜렉터 반환

        Args:
            device: 디바이스 정보

        Returns:
            적절한 콜렉터 인스턴스
        """
        output_dir = self._output_dir or './collected'

        if device.device_type == DeviceType.WINDOWS_PHYSICAL_DISK:
            # LocalMFTCollector 사용 (BitLocker 자동 감지 + 디렉토리 폴백)
            from collectors.artifact_collector import LocalMFTCollector, BASE_MFT_AVAILABLE
            if BASE_MFT_AVAILABLE:
                volume = device.metadata.get('volume', 'C')
                collector = LocalMFTCollector(output_dir, volume=volume)
                logger.info(f"Using LocalMFTCollector (mode: {collector.get_collection_mode()})")
                return collector
            else:
                # BaseMFTCollector 없으면 기존 ArtifactCollector 사용
                from collectors.artifact_collector import ArtifactCollector
                logger.info("Using legacy ArtifactCollector (BaseMFTCollector not available)")
                return ArtifactCollector(output_dir)

        elif device.device_type in (DeviceType.E01_IMAGE, DeviceType.RAW_IMAGE):
            from collectors.e01_artifact_collector import E01ArtifactCollector
            file_path = device.metadata.get('file_path')
            if not file_path:
                raise ValueError("No file_path in device metadata")
            collector = E01ArtifactCollector(file_path, output_dir)
            # 첫 번째 NTFS 파티션 자동 선택
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

        else:
            raise ValueError(f"Unknown device type: {device.device_type}")

    def _on_error(self, device_id: str, artifact: str, error: str):
        """에러 콜백"""
        self.error_occurred.emit(device_id, artifact, error)

    def cancel(self):
        """수집 취소"""
        logger.info("Cancelling collection...")
        self._cancelled.set()

        for task in self._tasks.values():
            if task.status == TaskStatus.RUNNING:
                task.status = TaskStatus.CANCELLED

        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

    def get_task(self, device_id: str) -> Optional[CollectionTask]:
        """디바이스별 작업 상태 조회"""
        return self._tasks.get(device_id)

    def get_all_tasks(self) -> Dict[str, CollectionTask]:
        """전체 작업 상태"""
        return self._tasks.copy()

    def get_results(self) -> List[CollectionResult]:
        """수집 결과"""
        return self._results.copy()

    @property
    def is_running(self) -> bool:
        """수집 진행 중 여부"""
        return any(
            task.status == TaskStatus.RUNNING
            for task in self._tasks.values()
        )

    @property
    def total_collected(self) -> int:
        """총 수집된 파일 수"""
        return sum(len(task.collected_files) for task in self._tasks.values())
