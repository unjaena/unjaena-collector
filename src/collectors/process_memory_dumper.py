"""
Process Memory Dumper Module

Windows 프로세스 메모리 덤프 수집 모듈.
MiniDumpWriteDump API를 사용하여 특정 프로세스의 메모리를 덤프합니다.

Usage:
    dumper = ProcessMemoryDumper()
    result = dumper.dump_process("KakaoTalk.exe", "output.dmp")
"""
import os
import ctypes
from ctypes import wintypes
from typing import Optional, List, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Windows API Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = 0x1F0FFF

# MiniDump Types
MiniDumpNormal = 0x00000000
MiniDumpWithDataSegs = 0x00000001
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpFilterMemory = 0x00000008
MiniDumpScanMemory = 0x00000010
MiniDumpWithUnloadedModules = 0x00000020
MiniDumpWithIndirectlyReferencedMemory = 0x00000040
MiniDumpFilterModulePaths = 0x00000080
MiniDumpWithProcessThreadData = 0x00000100
MiniDumpWithPrivateReadWriteMemory = 0x00000200
MiniDumpWithoutOptionalData = 0x00000400
MiniDumpWithFullMemoryInfo = 0x00000800
MiniDumpWithThreadInfo = 0x00001000
MiniDumpWithCodeSegs = 0x00002000

# TH32CS flags for CreateToolhelp32Snapshot
TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


class ProcessMemoryDumper:
    """Windows 프로세스 메모리 덤프 클래스"""

    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.dbghelp = ctypes.windll.dbghelp

    def find_process_by_name(self, process_name: str) -> List[Tuple[int, str]]:
        """
        프로세스 이름으로 PID 찾기

        Args:
            process_name: 프로세스 이름 (예: "KakaoTalk.exe")
                          UWP 앱도 매칭 (예: "WhatsApp.exe" → "WhatsApp.Root.exe")

        Returns:
            List of (pid, exe_name) tuples
        """
        processes = []
        process_name_lower = process_name.lower()
        # Extract stem for UWP matching: "WhatsApp.exe" → "whatsapp."
        # This matches WhatsApp.exe, WhatsApp.Root.exe, etc.
        process_stem_dot = ""
        if process_name_lower.endswith('.exe'):
            process_stem_dot = process_name_lower[:-4] + '.'  # "whatsapp."

        # CreateToolhelp32Snapshot
        snapshot = self.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == -1:
            logger.error("CreateToolhelp32Snapshot failed")
            return processes

        try:
            pe32 = PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

            # Process32First
            if self.kernel32.Process32First(snapshot, ctypes.byref(pe32)):
                while True:
                    exe_name = pe32.szExeFile.decode('utf-8', errors='ignore')
                    exe_lower = exe_name.lower()
                    # Match exact substring OR UWP stem prefix
                    # e.g., "whatsapp.exe" in "whatsapp.exe" → True (exact)
                    # e.g., "whatsapp.exe" in "whatsapp.root.exe" → False,
                    #   but "whatsapp." startswith check → True (UWP match)
                    if process_name_lower in exe_lower or (process_stem_dot and exe_lower.startswith(process_stem_dot)):
                        processes.append((pe32.th32ProcessID, exe_name))

                    # Process32Next
                    if not self.kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                        break
        finally:
            self.kernel32.CloseHandle(snapshot)

        return processes

    def dump_process(
        self,
        process_name: str,
        output_path: str,
        dump_type: int = None
    ) -> dict:
        """
        프로세스 메모리 덤프

        Args:
            process_name: 프로세스 이름 (예: "KakaoTalk.exe")
            output_path: 덤프 파일 저장 경로
            dump_type: MiniDump 타입 (기본: MiniDumpWithFullMemory)

        Returns:
            dict with 'success', 'pid', 'path', 'size', 'error'
        """
        result = {
            'success': False,
            'pid': None,
            'path': None,
            'size': 0,
            'error': None
        }

        if dump_type is None:
            # 전체 메모리 + 데이터 세그먼트 + 핸들 정보
            dump_type = MiniDumpWithFullMemory | MiniDumpWithDataSegs | MiniDumpWithHandleData

        # 프로세스 찾기
        processes = self.find_process_by_name(process_name)
        if not processes:
            result['error'] = f"Process not found: {process_name}"
            logger.warning(result['error'])
            return result

        pid, exe_name = processes[0]  # 첫 번째 매칭 프로세스 사용
        result['pid'] = pid
        logger.info(f"Found process: {exe_name} (PID: {pid})")

        # 프로세스 핸들 열기
        process_handle = self.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid
        )

        if not process_handle:
            error_code = self.kernel32.GetLastError()
            result['error'] = f"OpenProcess failed with error code: {error_code}"
            logger.error(result['error'])
            return result

        try:
            # 출력 파일 생성
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            file_handle = self.kernel32.CreateFileW(
                str(output_path),
                0x40000000,  # GENERIC_WRITE
                0,
                None,
                2,  # CREATE_ALWAYS
                0x80,  # FILE_ATTRIBUTE_NORMAL
                None
            )

            if file_handle == -1:
                error_code = self.kernel32.GetLastError()
                result['error'] = f"CreateFile failed with error code: {error_code}"
                logger.error(result['error'])
                return result

            try:
                # MiniDumpWriteDump 호출
                success = self.dbghelp.MiniDumpWriteDump(
                    process_handle,
                    pid,
                    file_handle,
                    dump_type,
                    None,
                    None,
                    None
                )

                if success:
                    result['success'] = True
                    result['path'] = str(output_path)
                    result['size'] = output_path.stat().st_size
                    logger.info(f"Memory dump created: {output_path} ({result['size']:,} bytes)")
                else:
                    error_code = self.kernel32.GetLastError()
                    result['error'] = f"MiniDumpWriteDump failed with error code: {error_code}"
                    logger.error(result['error'])

            finally:
                self.kernel32.CloseHandle(file_handle)

        finally:
            self.kernel32.CloseHandle(process_handle)

        return result

    def dump_process_lightweight(
        self,
        process_name: str,
        output_path: str
    ) -> dict:
        """
        Lightweight memory dump for forensic analysis

        MiniDumpWithPrivateReadWriteMemory를 사용하여
        힙, 스택 등 읽기/쓰기 가능한 메모리만 덤프
        """
        dump_type = (
            MiniDumpWithPrivateReadWriteMemory |
            MiniDumpWithDataSegs |
            MiniDumpWithProcessThreadData
        )
        return self.dump_process(process_name, output_path, dump_type)


