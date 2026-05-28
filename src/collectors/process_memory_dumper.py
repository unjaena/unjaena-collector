"""
Process Memory Dumper Module

Collects process memory dumps using the Windows MiniDumpWriteDump API.

Usage:
    dumper = ProcessMemoryDumper()
    result = dumper.dump_process("ExampleApp.exe", "output.dmp")
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
    """Windows process memory dump class."""

    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.dbghelp = ctypes.windll.dbghelp
        self.shell32 = ctypes.windll.shell32

    @staticmethod
    def _is_access_denied(error_code: int) -> bool:
        """Return True for Win32/HRESULT access-denied values."""
        return error_code == 5 or (error_code & 0xFFFFFFFF) == 0x80070005

    def is_elevated(self) -> bool:
        """Return whether the current process is running with admin rights."""
        try:
            return bool(self.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _format_windows_error(self, operation: str, error_code: int) -> str:
        message = f"{operation} failed with error code: {error_code}"
        if self._is_access_denied(error_code):
            message += (
                " (access denied; run the collector as Administrator so "
                "MiniDumpWriteDump can read messenger process memory)"
            )
        return message

    def find_process_by_name(self, process_name: str) -> List[Tuple[int, str]]:
        """
        Find PIDs by process name.

        Args:
            process_name: Process name (e.g. "ExampleApp.exe").
                          Also matches UWP apps (e.g. "PackagedApp.exe" -> "PackagedApp.Root.exe").

        Returns:
            List of (pid, exe_name) tuples.
        """
        processes = []
        process_name_lower = process_name.lower()
        # Extract stem for UWP matching: "PackagedApp.exe" → "packagedapp."
        # This matches PackagedApp.exe, PackagedApp.Root.exe, etc.
        process_stem_dot = ""
        if process_name_lower.endswith('.exe'):
            process_stem_dot = process_name_lower[:-4] + '.'  # "packagedapp."

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
                    # e.g., "packagedapp.exe" in "packagedapp.exe" → True (exact)
                    # e.g., "packagedapp.exe" in "packagedapp.root.exe" → False,
                    #   but "packagedapp." startswith check → True (UWP match)
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
        Dump process memory.

        Args:
            process_name: Process name (e.g. "ExampleApp.exe").
            output_path: Output file path for the dump.
            dump_type: MiniDump type (default: MiniDumpWithFullMemory).

        Returns:
            dict with 'success', 'pid', 'path', 'size', 'error'.
        """
        result = {
            'success': False,
            'pid': None,
            'path': None,
            'size': 0,
            'error': None,
            'requires_admin': False,
            'elevated': self.is_elevated(),
        }

        if dump_type is None:
            # Full memory + data segments + handle info
            dump_type = MiniDumpWithFullMemory | MiniDumpWithDataSegs | MiniDumpWithHandleData

        # Find process
        processes = self.find_process_by_name(process_name)
        if not processes:
            result['error'] = f"Process not found: {process_name}"
            logger.warning(result['error'])
            return result

        pid, exe_name = processes[0]  # Use first matching process
        result['pid'] = pid
        logger.info(f"Found process: {exe_name} (PID: {pid})")

        # Open process handle
        process_handle = self.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid
        )

        if not process_handle:
            error_code = self.kernel32.GetLastError()
            result['requires_admin'] = self._is_access_denied(error_code)
            result['error'] = self._format_windows_error("OpenProcess", error_code)
            logger.error(result['error'])
            return result

        try:
            # Create output file
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
                result['error'] = self._format_windows_error("CreateFile", error_code)
                logger.error(result['error'])
                return result

            try:
                # Call MiniDumpWriteDump
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
                    result['requires_admin'] = self._is_access_denied(error_code)
                    result['error'] = self._format_windows_error("MiniDumpWriteDump", error_code)
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
        Lightweight memory dump for forensic analysis.

        Uses MiniDumpWithPrivateReadWriteMemory to dump only
        private read/write memory regions (heap, stack, etc.).
        """
        dump_type = (
            MiniDumpWithPrivateReadWriteMemory |
            MiniDumpWithDataSegs |
            MiniDumpWithProcessThreadData
        )
        return self.dump_process(process_name, output_path, dump_type)


