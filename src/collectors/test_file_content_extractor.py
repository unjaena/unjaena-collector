from collectors.forensic_disk.file_content_extractor import (
    DataRun,
    FileContentExtractor,
)


class _FakeDisk:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, offset: int, size: int) -> bytes:
        return self._data[offset:offset + size]


def _make_extractor(disk: _FakeDisk) -> FileContentExtractor:
    extractor = FileContentExtractor.__new__(FileContentExtractor)
    extractor.disk = disk
    extractor.partition_offset = 0
    extractor.cluster_size = 512
    extractor.mft_record_size = 1024
    extractor._mft_runs = [DataRun(lcn=10, length=4, vcn_start=0)]
    extractor._full_mft_buf = None
    extractor._mft_buf = b""
    extractor._mft_buf_offset = -1
    extractor._mft_readahead_entries = 64
    return extractor


def test_read_mft_entry_supports_records_larger_than_cluster():
    disk_data = bytearray(16 * 512)
    record = bytearray(1024)
    record[:4] = b"FILE"
    disk_data[10 * 512:12 * 512] = record

    extractor = _make_extractor(_FakeDisk(bytes(disk_data)))

    entry = extractor.read_mft_entry(0)

    assert len(entry) == 1024
    assert entry[:4] == b"FILE"


def test_read_mft_entry_uses_logical_mft_stream_offsets():
    disk_data = bytearray(16 * 512)
    record = bytearray(1024)
    record[:4] = b"FILE"
    record[16:20] = b"ONE!"
    disk_data[12 * 512:14 * 512] = record

    extractor = _make_extractor(_FakeDisk(bytes(disk_data)))

    entry = extractor.read_mft_entry(1)

    assert len(entry) == 1024
    assert entry[:4] == b"FILE"
    assert entry[16:20] == b"ONE!"
