"""Artifact collector modules"""
from .artifact_collector import ArtifactCollector, ARTIFACT_TYPES

__all__ = ['ArtifactCollector', 'ARTIFACT_TYPES']

try:
    from .android_wifi_collector import AndroidWiFiCollector, AndroidWiFiDeviceScanner, wifi_adb_available
except ImportError:
    pass

try:
    from .android_frida_collector import AndroidFridaCollector, frida_available
except ImportError:
    pass

try:
    from .android_fastboot_collector import AndroidFastbootCollector, fastboot_available
except ImportError:
    pass

try:
    from .android_edl_collector import AndroidEDLCollector, edl_available, detect_qualcomm_edl_device
except ImportError:
    pass

try:
    from .android_mtk_collector import AndroidMTKCollector, mtk_available, detect_mtk_brom_device
except ImportError:
    pass
