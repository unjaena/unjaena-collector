from utils.bitlocker.luks_backend import LUKSBackend, _UnifiedDiskReaderAdapter
from utils.bitlocker.unified_disk_reader import DiskInfo, DiskSourceType, UnifiedDiskReader


class _FakeStream:
    size = 4096

    def __init__(self):
        self.position = 0
        self.closed = False

    def seek(self, offset):
        self.position = offset

    def read(self, size):
        return bytes([self.position % 256]) * size

    def close(self):
        self.closed = True


def test_luks_backend_read_uses_decrypted_stream():
    backend = LUKSBackend.__new__(LUKSBackend)
    backend._luks = object()
    backend._stream = _FakeStream()
    backend._source_fh = None
    backend._is_unlocked = True

    assert backend.read(7, 3) == b"\x07\x07\x07"


def test_luks_backend_close_closes_stream():
    backend = LUKSBackend.__new__(LUKSBackend)
    stream = _FakeStream()
    backend._stream = stream
    backend._luks = None
    backend._source_fh = None
    backend._is_open = True
    backend._is_unlocked = True

    backend.close()

    assert stream.closed is True
    assert backend._stream is None
    assert backend._is_unlocked is False


class _FakeReader(UnifiedDiskReader):
    def __init__(self, data: bytes):
        super().__init__()
        self.data = data
        self._disk_size = len(data)
        self._is_open = True

    def read(self, offset: int, size: int) -> bytes:
        return self.data[offset:offset + size]

    def get_size(self) -> int:
        return len(self.data)

    def get_disk_info(self) -> DiskInfo:
        return DiskInfo(DiskSourceType.RAW_IMAGE, len(self.data))

    def close(self) -> None:
        self._is_open = False


def test_unified_disk_reader_adapter_is_file_like():
    adapter = _UnifiedDiskReaderAdapter(_FakeReader(b"abcdef"))

    assert adapter.tell() == 0
    assert adapter.read(2) == b"ab"
    assert adapter.tell() == 2
    assert adapter.seek(-2, 2) == 4
    assert adapter.read() == b"ef"
    assert adapter.seekable() is True
    assert adapter.readable() is True
    assert adapter.writable() is False
