"""
Memory Forensics Collector Module

Memory forensics collection and analysis module.
Supports memory dump collection using WinPmem and analysis using Volatility3.

Collectable Artifacts:
- memory_process: Process list
- memory_network: Network connection information
- memory_module: Loaded DLLs/modules
- memory_handle: Handle information
- memory_registry: Registry hives in memory
- memory_credential: Credential information
- memory_malware: Malware detection (YARA rule-based)

Requirements:
    - volatility3>=2.5.0
    - yara-python>=4.3.0 (optional, for malware detection)
    - WinPmem driver (bundled in resources/)
"""
import os
import sys
import ctypes
import hashlib
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List, Callable

# Check for Volatility3 availability
try:
    import volatility3
    from volatility3.framework import contexts, automagic
    from volatility3.framework.configuration import requirements
    from volatility3.plugins.windows import pslist, netstat, dlllist, handles, registry
    VOLATILITY_AVAILABLE = True
except ImportError:
    VOLATILITY_AVAILABLE = False

# Check for YARA availability
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


# Memory artifact type definitions
MEMORY_ARTIFACT_TYPES = {
    'memory_dump': {
        'name': 'Memory Dump',
        'description': 'Full physical memory acquisition using WinPmem',
        'requires_admin': True,
        'requires_driver': True,
    },
    'memory_process': {
        'name': 'Process List',
        'description': 'Running processes from memory',
        'volatility_plugin': 'windows.pslist',
        'requires_dump': True,
    },
    'memory_network': {
        'name': 'Network Connections',
        'description': 'Active network connections from memory',
        'volatility_plugin': 'windows.netstat',
        'requires_dump': True,
    },
    'memory_module': {
        'name': 'Loaded Modules',
        'description': 'DLLs and modules loaded in memory',
        'volatility_plugin': 'windows.dlllist',
        'requires_dump': True,
    },
    'memory_handle': {
        'name': 'Handles',
        'description': 'Open handles (files, registry, etc.)',
        'volatility_plugin': 'windows.handles',
        'requires_dump': True,
    },
    'memory_registry': {
        'name': 'Registry Hives',
        'description': 'Registry hives loaded in memory',
        'volatility_plugin': 'windows.registry.hivelist',
        'requires_dump': True,
    },
    'memory_credential': {
        'name': 'Credentials',
        'description': 'Password hashes and credentials',
        'volatility_plugin': 'windows.hashdump',
        'requires_dump': True,
        'requires_admin': True,
    },
    'memory_malware': {
        'name': 'Malware Detection',
        'description': 'Suspicious memory regions and injected code',
        'volatility_plugin': 'windows.malfind',
        'requires_dump': True,
        'yara_scan': True,
    },
}


def is_admin() -> bool:
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_winpmem_path() -> Optional[Path]:
    """Get path to bundled WinPmem executable"""
    # Check various locations
    possible_paths = [
        Path(__file__).parent.parent / 'resources' / 'winpmem_mini_x64.exe',
        Path(__file__).parent.parent.parent / 'resources' / 'winpmem_mini_x64.exe',
        Path(sys.executable).parent / 'resources' / 'winpmem_mini_x64.exe',
    ]

    for path in possible_paths:
        if path.exists():
            return path

    return None


class WinPmemDumper:
    """
    Live memory dump collection using WinPmem

    WinPmem dumps Windows physical memory in raw format.
    Administrator privileges required.
    """

    def __init__(self, winpmem_path: Optional[Path] = None):
        """
        Initialize WinPmem dumper.

        Args:
            winpmem_path: Path to winpmem executable. If None, uses bundled version.
        """
        self.winpmem_path = winpmem_path or get_winpmem_path()
        if self.winpmem_path is None:
            raise FileNotFoundError(
                "WinPmem executable not found. "
                "Please place winpmem_mini_x64.exe in resources/ directory."
            )

        self._process: Optional[subprocess.Popen] = None
        self._cancelled = False

    def get_system_memory_size(self) -> int:
        """Get total physical memory size in bytes"""
        try:
            import psutil
            return psutil.virtual_memory().total
        except ImportError:
            # Fallback: use Windows API
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(stat)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return stat.ullTotalPhys

    def acquire_memory(
        self,
        output_path: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        format: str = 'raw',
        timeout_seconds: int = 1800,  # 30 minute default timeout
        stall_timeout_seconds: int = 120  # 2 minute timeout if no progress
    ) -> Dict[str, Any]:
        """
        Acquire full physical memory dump.

        Args:
            output_path: Path to save the memory dump
            progress_callback: Callback function(current_bytes, total_bytes)
            format: Output format ('raw' or 'aff4')
            timeout_seconds: Maximum total time for acquisition (default: 1800 = 30 minutes)
            stall_timeout_seconds: Timeout if no progress (default: 120 = 2 minutes)

        Returns:
            Dictionary with acquisition metadata

        Raises:
            PermissionError: If not running as administrator
            RuntimeError: If acquisition fails
            TimeoutError: If acquisition times out
        """
        if not is_admin():
            raise PermissionError("Memory acquisition requires administrator privileges")

        self._cancelled = False
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        total_memory = self.get_system_memory_size()
        start_time = datetime.utcnow()

        # Build command
        cmd = [str(self.winpmem_path)]

        if format == 'aff4':
            cmd.extend(['-o', str(output_path)])
        else:
            # Raw format - output to file
            cmd.append(str(output_path))

        try:
            # Run WinPmem
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Monitor progress (approximate based on file size)
            import time
            last_size = 0
            last_progress_time = time.time()

            while self._process.poll() is None:
                if self._cancelled:
                    self._process.terminate()
                    raise RuntimeError("Memory acquisition cancelled by user")

                current_time = time.time()
                elapsed_total = current_time - start_time.timestamp()

                # Check total timeout
                if elapsed_total > timeout_seconds:
                    self._process.terminate()
                    raise TimeoutError(
                        f"Memory acquisition timed out after {timeout_seconds}s. "
                        f"Total memory: {total_memory // (1024**3)}GB"
                    )

                if output_path.exists():
                    current_size = output_path.stat().st_size

                    if current_size != last_size:
                        # Reset timer if progress is being made
                        last_progress_time = current_time
                        if progress_callback:
                            progress_callback(current_size, total_memory)
                        last_size = current_size
                    else:
                        # Check stall timeout if no progress
                        stall_time = current_time - last_progress_time
                        if stall_time > stall_timeout_seconds and last_size > 0:
                            self._process.terminate()
                            raise TimeoutError(
                                f"Memory acquisition stalled for {stall_timeout_seconds}s. "
                                f"Progress: {last_size // (1024**2)}MB / {total_memory // (1024**2)}MB"
                            )
                else:
                    # File not yet created - check startup timeout
                    if current_time - start_time.timestamp() > 30:  # Must start within 30 seconds
                        self._process.terminate()
                        raise TimeoutError("WinPmem failed to start within 30 seconds")

                # Small delay to prevent busy-waiting
                time.sleep(0.5)

            # Check result
            if self._process.returncode != 0:
                stderr = self._process.stderr.read().decode('utf-8', errors='ignore')
                raise RuntimeError(f"WinPmem failed: {stderr}")

            # Final progress update
            if progress_callback and output_path.exists():
                progress_callback(output_path.stat().st_size, total_memory)

            end_time = datetime.utcnow()

            # Calculate hash
            sha256 = hashlib.sha256()
            with open(output_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)

            return {
                'artifact_type': 'memory_dump',
                'output_path': str(output_path),
                'filename': output_path.name,
                'format': format,
                'size': output_path.stat().st_size,
                'expected_size': total_memory,
                'sha256': sha256.hexdigest(),
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': (end_time - start_time).total_seconds(),
                'winpmem_version': self._get_winpmem_version(),
                'collection_method': 'winpmem_physical_memory',
            }

        except Exception as e:
            # Clean up partial file on failure
            if output_path.exists() and self._cancelled:
                output_path.unlink()
            raise
        finally:
            self._process = None

    def cancel(self):
        """Cancel ongoing memory acquisition"""
        self._cancelled = True
        if self._process:
            self._process.terminate()

    def _get_winpmem_version(self) -> str:
        """Get WinPmem version string"""
        try:
            result = subprocess.run(
                [str(self.winpmem_path), '-h'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Parse version from output
            for line in result.stdout.split('\n'):
                if 'version' in line.lower():
                    return line.strip()
            return 'unknown'
        except Exception:
            return 'unknown'


class VolatilityAnalyzer:
    """
    Memory analysis using Volatility3

    Extracts forensic artifacts from memory dumps.
    """

    def __init__(self, memory_dump_path: str):
        """
        Initialize Volatility analyzer.

        Args:
            memory_dump_path: Path to memory dump file
        """
        if not VOLATILITY_AVAILABLE:
            raise ImportError(
                "Volatility3 is not installed. "
                "Install with: pip install volatility3"
            )

        self.dump_path = Path(memory_dump_path)
        if not self.dump_path.exists():
            raise FileNotFoundError(f"Memory dump not found: {memory_dump_path}")

        self._context = None
        self._automagics = None

    def _initialize_context(self):
        """Initialize Volatility context (lazy loading)"""
        if self._context is not None:
            return

        # This is a simplified initialization
        # Full implementation would require more Volatility3 setup
        self._context = contexts.Context()
        self._automagics = automagic.available(self._context)

    def analyze_processes(self) -> Generator[Dict[str, Any], None, None]:
        """
        Extract process list from memory.

        Yields:
            Process information dictionaries
        """
        self._initialize_context()

        # Note: This is a placeholder implementation
        # Full implementation requires proper Volatility3 plugin execution
        # which involves complex context setup

        yield {
            'artifact_type': 'memory_process',
            'status': 'analysis_pending',
            'message': 'Separate execution required for Volatility3 analysis.',
            'command': f'vol -f {self.dump_path} windows.pslist',
        }

    def analyze_network(self) -> Generator[Dict[str, Any], None, None]:
        """Extract network connections from memory"""
        self._initialize_context()

        yield {
            'artifact_type': 'memory_network',
            'status': 'analysis_pending',
            'command': f'vol -f {self.dump_path} windows.netstat',
        }

    def analyze_modules(self) -> Generator[Dict[str, Any], None, None]:
        """Extract loaded modules from memory"""
        self._initialize_context()

        yield {
            'artifact_type': 'memory_module',
            'status': 'analysis_pending',
            'command': f'vol -f {self.dump_path} windows.dlllist',
        }

    def analyze_handles(self) -> Generator[Dict[str, Any], None, None]:
        """Extract handle information from memory"""
        self._initialize_context()

        yield {
            'artifact_type': 'memory_handle',
            'status': 'analysis_pending',
            'command': f'vol -f {self.dump_path} windows.handles',
        }

    def analyze_registry(self) -> Generator[Dict[str, Any], None, None]:
        """Extract registry hives from memory"""
        self._initialize_context()

        yield {
            'artifact_type': 'memory_registry',
            'status': 'analysis_pending',
            'command': f'vol -f {self.dump_path} windows.registry.hivelist',
        }

    def analyze_credentials(self) -> Generator[Dict[str, Any], None, None]:
        """Extract credential information from memory"""
        self._initialize_context()

        yield {
            'artifact_type': 'memory_credential',
            'status': 'analysis_pending',
            'command': f'vol -f {self.dump_path} windows.hashdump',
            'warning': 'Requires SYSTEM and SAM hives in memory',
        }

    def detect_malware(
        self,
        yara_rules_path: Optional[str] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Detect suspicious memory regions and potential malware.

        Args:
            yara_rules_path: Optional path to custom YARA rules

        Yields:
            Malware detection results
        """
        self._initialize_context()

        results = {
            'artifact_type': 'memory_malware',
            'status': 'analysis_pending',
            'commands': [
                f'vol -f {self.dump_path} windows.malfind',
                f'vol -f {self.dump_path} windows.vadinfo',
            ],
        }

        if YARA_AVAILABLE and yara_rules_path:
            results['yara_scan'] = {
                'rules_path': yara_rules_path,
                'status': 'pending',
            }

        yield results


class MemoryCollector:
    """
    Integrated memory forensics collection class

    Integrates WinPmem memory dump and Volatility3 analysis.
    """

    def __init__(self, output_dir: str):
        """
        Initialize memory collector.

        Args:
            output_dir: Directory to store collected artifacts
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.dumper: Optional[WinPmemDumper] = None
        self.analyzer: Optional[VolatilityAnalyzer] = None
        self.memory_dump_path: Optional[Path] = None

    def is_available(self) -> Dict[str, bool]:
        """Check availability of memory forensics components"""
        winpmem_path = get_winpmem_path()

        return {
            'winpmem': winpmem_path is not None,
            'volatility3': VOLATILITY_AVAILABLE,
            'yara': YARA_AVAILABLE,
            'admin': is_admin(),
        }

    def acquire_memory(
        self,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Acquire physical memory dump.

        Args:
            progress_callback: Progress callback function

        Returns:
            Tuple of (dump_path, metadata)
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        dump_filename = f"memory_dump_{timestamp}.raw"
        dump_path = self.output_dir / 'memory_dump' / dump_filename
        dump_path.parent.mkdir(exist_ok=True)

        self.dumper = WinPmemDumper()
        metadata = self.dumper.acquire_memory(
            str(dump_path),
            progress_callback=progress_callback
        )

        self.memory_dump_path = dump_path
        return str(dump_path), metadata

    def cancel_acquisition(self):
        """Cancel ongoing memory acquisition"""
        if self.dumper:
            self.dumper.cancel()

    def analyze(
        self,
        artifact_type: str,
        memory_dump_path: Optional[str] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Analyze memory dump for specific artifact type.

        Args:
            artifact_type: Type of artifact to extract
            memory_dump_path: Optional path to memory dump (uses last acquired if None)

        Yields:
            Tuple of (output_path, metadata)
        """
        dump_path = memory_dump_path or self.memory_dump_path
        if dump_path is None:
            raise ValueError("No memory dump available. Run acquire_memory() first.")

        if not VOLATILITY_AVAILABLE:
            yield (
                str(dump_path),
                {
                    'artifact_type': artifact_type,
                    'status': 'volatility_not_available',
                    'message': 'Volatility3 is not installed.',
                    'install_command': 'pip install volatility3',
                }
            )
            return

        self.analyzer = VolatilityAnalyzer(str(dump_path))

        # Map artifact types to analyzer methods
        analyzers = {
            'memory_process': self.analyzer.analyze_processes,
            'memory_network': self.analyzer.analyze_network,
            'memory_module': self.analyzer.analyze_modules,
            'memory_handle': self.analyzer.analyze_handles,
            'memory_registry': self.analyzer.analyze_registry,
            'memory_credential': self.analyzer.analyze_credentials,
            'memory_malware': self.analyzer.detect_malware,
        }

        if artifact_type not in analyzers:
            raise ValueError(f"Unknown memory artifact type: {artifact_type}")

        analyzer_func = analyzers[artifact_type]

        for result in analyzer_func():
            result['memory_dump_path'] = str(dump_path)
            result['collected_at'] = datetime.utcnow().isoformat()
            yield str(dump_path), result

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """Get list of available memory artifact types"""
        availability = self.is_available()
        artifacts = []

        for type_id, info in MEMORY_ARTIFACT_TYPES.items():
            available = True
            reasons = []

            if info.get('requires_admin') and not availability['admin']:
                available = False
                reasons.append('Administrator privileges required')

            if info.get('requires_driver') and not availability['winpmem']:
                available = False
                reasons.append('WinPmem driver required')

            if info.get('requires_dump') and not availability['volatility3']:
                available = False
                reasons.append('Volatility3 required')

            if info.get('yara_scan') and not availability['yara']:
                reasons.append('YARA not installed (optional)')

            artifacts.append({
                'type': type_id,
                'name': info['name'],
                'description': info['description'],
                'available': available,
                'reasons': reasons,
                'volatility_plugin': info.get('volatility_plugin'),
            })

        return artifacts


def get_memory_info() -> Dict[str, Any]:
    """Get current system memory information"""
    try:
        import psutil
        mem = psutil.virtual_memory()
        return {
            'total_gb': round(mem.total / (1024**3), 2),
            'available_gb': round(mem.available / (1024**3), 2),
            'used_percent': mem.percent,
            'estimated_dump_size_gb': round(mem.total / (1024**3), 2),
        }
    except ImportError:
        return {
            'total_gb': 'unknown',
            'available_gb': 'unknown',
            'used_percent': 'unknown',
            'estimated_dump_size_gb': 'unknown',
        }


if __name__ == "__main__":
    print("Memory Forensics Collector")
    print("=" * 50)

    print("\n[System Info]")
    mem_info = get_memory_info()
    for key, value in mem_info.items():
        print(f"  {key}: {value}")

    print("\n[Component Availability]")
    collector = MemoryCollector("./memory_output")
    availability = collector.is_available()
    for component, available in availability.items():
        status = "OK" if available else "N/A"
        print(f"  [{status}] {component}")

    print("\n[Available Artifacts]")
    for artifact in collector.get_available_artifacts():
        status = "OK" if artifact['available'] else "N/A"
        reasons = f" ({', '.join(artifact['reasons'])})" if artifact['reasons'] else ""
        print(f"  [{status}] {artifact['type']}: {artifact['name']}{reasons}")
