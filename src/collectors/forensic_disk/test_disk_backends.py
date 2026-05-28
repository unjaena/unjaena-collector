from collectors.forensic_disk.disk_backends import RAWImageBackend


class _FakeBackend:
    def __init__(self, image: bytes):
        self.image = image

    def read(self, offset: int, size: int) -> bytes:
        chunk = self.image[offset:offset + size]
        return chunk + (b"\x00" * max(0, size - len(chunk)))


def _detect_fake_filesystem(image: bytes) -> str:
    from collectors.forensic_disk.forensic_disk_accessor import ForensicDiskAccessor
    accessor = ForensicDiskAccessor.__new__(ForensicDiskAccessor)
    accessor._backend = _FakeBackend(image)
    return accessor._detect_filesystem(0)


def _ext_superblock_image(*, compat: int = 0, incompat: int = 0) -> bytes:
    image = bytearray(4096)
    sb = 1024
    image[sb + 56:sb + 58] = (0xEF53).to_bytes(2, "little")
    image[sb + 92:sb + 96] = compat.to_bytes(4, "little")
    image[sb + 96:sb + 100] = incompat.to_bytes(4, "little")
    return bytes(image)


def test_ext3_detection_uses_compat_journal_flag():
    assert _detect_fake_filesystem(_ext_superblock_image(compat=0x04)) == "ext3"


def test_ext4_detection_prefers_extents_incompat_flag():
    assert _detect_fake_filesystem(_ext_superblock_image(compat=0x04, incompat=0x40)) == "ext4"


def test_luks_detection_uses_luks_header_signature():
    image = bytearray(4096)
    image[:6] = b"LUKS\xba\xbe"
    assert _detect_fake_filesystem(bytes(image)) == "LUKS"
