# Collector Tools

iOS 포렌식 수집에 필요한 도구들을 관리하는 디렉토리입니다.

## pymobiledevice3

iOS 기기 직접 연결을 위한 Pure Python 라이브러리입니다.

### 설치

```bash
pip install pymobiledevice3
```

### 기능

pymobiledevice3는 다음 기능을 제공합니다:

| 기능 | 설명 |
|------|------|
| 기기 열거 | USB로 연결된 iOS 기기 목록 조회 |
| 기기 정보 | UDID, 모델, iOS 버전 등 상세 정보 |
| 시스템 로그 | 실시간 iOS 시스템 로그 수집 |
| 크래시 리포트 | 앱 크래시 리포트 추출 |
| 설치된 앱 | 설치된 앱 목록 조회 |
| 백업 생성 | iOS 백업 생성 |

### 라이선스

pymobiledevice3는 **GPL-3.0** 라이선스로 배포됩니다.

- 프로젝트: https://github.com/doronz88/pymobiledevice3
- 라이선스: https://www.gnu.org/licenses/gpl-3.0.html

### 사용 조건

- iOS 기기가 USB로 연결되어 있어야 함
- 기기에서 "이 컴퓨터 신뢰" 승인 필요
- Windows의 경우 iTunes 또는 Apple Mobile Device Support 드라이버 필요

### 문제 해결

**"기기를 찾을 수 없습니다"**
1. USB 케이블 및 연결 확인
2. 기기 잠금 해제
3. "이 컴퓨터 신뢰" 팝업 확인
4. iTunes 설치 확인 (드라이버 포함)

**"pairing 오류"**
1. 기기에서 "이 컴퓨터 신뢰"를 다시 확인
2. Windows: 관리자 권한으로 실행
3. macOS/Linux: `sudo` 사용

**"pymobiledevice3 설치 실패"**
```bash
# pip 업그레이드
pip install --upgrade pip

# 재설치
pip install --force-reinstall pymobiledevice3
```

### 코드 예제

```python
from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.lockdown import create_using_usbmux

# 연결된 기기 목록
devices = list_devices()
for device in devices:
    print(f"UDID: {device.serial}")

# 기기 정보 조회
if devices:
    lockdown = create_using_usbmux(serial=devices[0].serial)
    info = lockdown.all_values
    print(f"Device: {info.get('DeviceName')}")
    print(f"iOS: {info.get('ProductVersion')}")
```
