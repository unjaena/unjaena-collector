"""
P2-2: 사용자 친화적 에러 메시지 모듈

기술적 에러 메시지를 사용자가 이해하기 쉬운 한글 메시지로 변환합니다.
"""
from dataclasses import dataclass
from typing import Optional, Dict, List
import re


@dataclass
class UserFriendlyError:
    """사용자 친화적 에러 정보"""
    title: str              # 에러 제목 (짧은 설명)
    message: str            # 에러 상세 메시지
    solution: str           # 해결 방법
    error_code: str         # 내부 에러 코드 (지원 문의용)
    is_recoverable: bool    # 재시도 가능 여부


# 에러 패턴 매핑 (정규식 패턴 → 사용자 친화적 메시지)
# 주의: 패턴은 순서대로 매칭되므로 우선순위가 높은 패턴을 먼저 배치
ERROR_PATTERNS: List[Dict] = [
    # 취소 관련 (최상위 우선순위 - 다른 패턴보다 먼저 매칭되어야 함)
    {
        "pattern": r"(CANCELLED|409.*cancelled|취소됨)",
        "title": "수집 취소됨",
        "message": "CANCELLED: 서버에서 수집이 취소되었습니다.",
        "solution": "사용자 또는 관리자가 수집을 취소했습니다. 새로 수집을 시작하려면 웹 플랫폼에서 다시 시작하세요.",
        "error_code": "CANCELLED",
        "is_recoverable": False,
    },

    # 네트워크 관련
    {
        "pattern": r"(Cannot connect|ConnectionError|Connection refused|Unable to connect)",
        "title": "서버 연결 실패",
        "message": "서버에 연결할 수 없습니다.",
        "solution": "1. 인터넷 연결 상태를 확인하세요.\n2. 방화벽이 연결을 차단하고 있는지 확인하세요.\n3. 서버 URL이 올바른지 확인하세요.",
        "error_code": "NET_CONN_FAIL",
        "is_recoverable": True,
    },
    {
        "pattern": r"(timeout|Timeout|timed out)",
        "title": "연결 시간 초과",
        "message": "서버 응답을 기다리는 중 시간이 초과되었습니다.",
        "solution": "1. 네트워크 상태가 불안정할 수 있습니다. 잠시 후 다시 시도하세요.\n2. 대용량 파일 업로드 시 시간이 더 소요될 수 있습니다.",
        "error_code": "NET_TIMEOUT",
        "is_recoverable": True,
    },
    {
        "pattern": r"(SSL|TLS|certificate|CERTIFICATE)",
        "title": "보안 연결 오류",
        "message": "보안 연결(HTTPS)을 설정하는 중 오류가 발생했습니다.",
        "solution": "1. 시스템 날짜와 시간이 올바른지 확인하세요.\n2. 관리자에게 서버 인증서 상태를 문의하세요.",
        "error_code": "NET_SSL_FAIL",
        "is_recoverable": False,
    },

    # 인증 관련
    {
        "pattern": r"(401|Unauthorized|unauthorized|인증)",
        "title": "인증 실패",
        "message": "서버 인증에 실패했습니다.",
        "solution": "1. 세션 토큰이 만료되었을 수 있습니다. 새 토큰을 발급받으세요.\n2. 웹 플랫폼에서 로그인 상태를 확인하세요.",
        "error_code": "AUTH_FAIL",
        "is_recoverable": True,
    },
    {
        "pattern": r"(403|Forbidden|forbidden|권한)",
        "title": "접근 권한 없음",
        "message": "해당 작업을 수행할 권한이 없습니다.",
        "solution": "1. 관리자에게 권한 설정을 문의하세요.\n2. 올바른 계정으로 로그인했는지 확인하세요.",
        "error_code": "AUTH_PERM",
        "is_recoverable": False,
    },
    {
        "pattern": r"(토큰.*만료|expired|Expired)",
        "title": "토큰 만료",
        "message": "세션 토큰이 만료되었습니다.",
        "solution": "웹 플랫폼에서 새 토큰을 발급받아 입력하세요.",
        "error_code": "AUTH_TOKEN_EXP",
        "is_recoverable": True,
    },
    {
        "pattern": r"(토큰.*사용|already used|이미 사용)",
        "title": "토큰 재사용 불가",
        "message": "이 토큰은 이미 사용되었습니다.",
        "solution": "보안을 위해 토큰은 한 번만 사용할 수 있습니다. 웹 플랫폼에서 새 토큰을 발급받으세요.",
        "error_code": "AUTH_TOKEN_USED",
        "is_recoverable": True,
    },

    # 파일 관련
    {
        "pattern": r"(FileNotFoundError|No such file|파일.*찾을 수 없|not found)",
        "title": "파일을 찾을 수 없음",
        "message": "요청한 파일이 존재하지 않습니다.",
        "solution": "1. 파일이 삭제되었거나 이동되었을 수 있습니다.\n2. 안티바이러스 프로그램이 파일을 격리했는지 확인하세요.",
        "error_code": "FILE_NOT_FOUND",
        "is_recoverable": False,
    },
    {
        "pattern": r"(PermissionError|Permission denied|액세스.*거부|접근 거부)",
        "title": "파일 접근 권한 없음",
        "message": "파일에 접근할 수 없습니다.",
        "solution": "1. 관리자 권한으로 프로그램을 실행하세요.\n2. 다른 프로그램이 파일을 사용 중인지 확인하세요.",
        "error_code": "FILE_PERM",
        "is_recoverable": True,
    },
    {
        "pattern": r"(disk.*full|디스크.*공간|No space left)",
        "title": "디스크 공간 부족",
        "message": "저장 공간이 부족합니다.",
        "solution": "1. 불필요한 파일을 삭제하여 공간을 확보하세요.\n2. 다른 드라이브를 사용해보세요.",
        "error_code": "FILE_DISK_FULL",
        "is_recoverable": True,
    },

    # 수집 관련
    {
        "pattern": r"(MFT|$MFT|마스터 파일 테이블)",
        "title": "MFT 수집 오류",
        "message": "마스터 파일 테이블(MFT) 수집 중 오류가 발생했습니다.",
        "solution": "1. 관리자 권한으로 프로그램을 실행하세요.\n2. 대상 드라이브가 NTFS 파일 시스템인지 확인하세요.",
        "error_code": "COLLECT_MFT",
        "is_recoverable": True,
    },
    {
        "pattern": r"(레지스트리|Registry|HKEY_)",
        "title": "레지스트리 수집 오류",
        "message": "Windows 레지스트리 수집 중 오류가 발생했습니다.",
        "solution": "1. 관리자 권한으로 프로그램을 실행하세요.\n2. 일부 레지스트리 키는 보호되어 있을 수 있습니다.",
        "error_code": "COLLECT_REG",
        "is_recoverable": True,
    },

    # 암호화 관련
    {
        "pattern": r"(encrypt|Encrypt|암호화)",
        "title": "암호화 오류",
        "message": "파일 암호화 중 오류가 발생했습니다.",
        "solution": "1. 파일이 손상되지 않았는지 확인하세요.\n2. 시스템 메모리가 부족할 수 있습니다.",
        "error_code": "CRYPTO_FAIL",
        "is_recoverable": True,
    },

    # 업로드 관련
    {
        "pattern": r"(upload|Upload|업로드)",
        "title": "업로드 오류",
        "message": "파일 업로드 중 오류가 발생했습니다.",
        "solution": "1. 네트워크 연결 상태를 확인하세요.\n2. 파일 크기가 서버 제한을 초과하지 않는지 확인하세요.\n3. 잠시 후 다시 시도하세요.",
        "error_code": "UPLOAD_FAIL",
        "is_recoverable": True,
    },
    {
        "pattern": r"(413|Payload Too Large|too large|크기.*초과)",
        "title": "파일 크기 초과",
        "message": "파일 크기가 서버 허용 한도를 초과했습니다.",
        "solution": "대용량 파일은 분할 업로드가 필요합니다. 관리자에게 문의하세요.",
        "error_code": "UPLOAD_SIZE",
        "is_recoverable": False,
    },

    # 동시 수집 관련 (409 Conflict)
    {
        "pattern": r"(409|concurrent_collection|case_collection_in_progress|이미.*수집.*진행)",
        "title": "수집 세션 충돌",
        "message": "이 케이스에 이미 수집이 진행 중이거나 이전 수집 세션이 정리되지 않았습니다.",
        "solution": "1. 잠시 기다렸다가 다시 시도하세요 (5분 후 자동 정리됨).\n2. 웹 플랫폼에서 케이스를 취소 후 새로 토큰을 발급받으세요.\n3. 문제가 지속되면 관리자에게 문의하세요.",
        "error_code": "COLLECT_CONFLICT",
        "is_recoverable": True,
    },

    # 서버 관련
    {
        "pattern": r"(500|Internal Server Error|서버 오류)",
        "title": "서버 내부 오류",
        "message": "서버에서 오류가 발생했습니다.",
        "solution": "서버 관리자에게 문의하세요. 잠시 후 다시 시도해도 됩니다.",
        "error_code": "SRV_INTERNAL",
        "is_recoverable": True,
    },
    {
        "pattern": r"(502|503|504|Service Unavailable|서버.*불가)",
        "title": "서버 일시적 장애",
        "message": "서버가 일시적으로 서비스할 수 없는 상태입니다.",
        "solution": "서버 점검 중일 수 있습니다. 잠시 후 다시 시도하세요.",
        "error_code": "SRV_UNAVAIL",
        "is_recoverable": True,
    },
]


def translate_error(technical_error: str) -> UserFriendlyError:
    """
    기술적 에러 메시지를 사용자 친화적 메시지로 변환합니다.

    Args:
        technical_error: 원본 기술적 에러 메시지

    Returns:
        UserFriendlyError 객체
    """
    if not technical_error:
        return UserFriendlyError(
            title="알 수 없는 오류",
            message="오류가 발생했습니다.",
            solution="프로그램을 다시 시작하거나 관리자에게 문의하세요.",
            error_code="UNKNOWN",
            is_recoverable=True,
        )

    # 패턴 매칭으로 적절한 에러 메시지 찾기
    for error_info in ERROR_PATTERNS:
        if re.search(error_info["pattern"], technical_error, re.IGNORECASE):
            return UserFriendlyError(
                title=error_info["title"],
                message=error_info["message"],
                solution=error_info["solution"],
                error_code=error_info["error_code"],
                is_recoverable=error_info["is_recoverable"],
            )

    # 매칭되는 패턴이 없으면 기본 에러 반환
    return UserFriendlyError(
        title="오류 발생",
        message=f"작업 중 오류가 발생했습니다.",
        solution="자세한 내용은 로그를 확인하거나 관리자에게 문의하세요.",
        error_code="GENERAL",
        is_recoverable=True,
    )


def format_error_for_display(error: UserFriendlyError, show_details: bool = True) -> str:
    """
    에러 정보를 표시용 문자열로 포맷합니다.

    Args:
        error: UserFriendlyError 객체
        show_details: 상세 정보 포함 여부

    Returns:
        포맷된 에러 메시지 문자열
    """
    lines = [
        f"⚠️ {error.title}",
        "",
        error.message,
        "",
        "💡 해결 방법:",
        error.solution,
    ]

    if show_details:
        lines.extend([
            "",
            f"오류 코드: {error.error_code}",
        ])

        if error.is_recoverable:
            lines.append("✅ 이 오류는 재시도로 해결될 수 있습니다.")
        else:
            lines.append("❌ 이 오류는 설정 변경이 필요합니다.")

    return "\n".join(lines)


def get_error_title(technical_error: str) -> str:
    """에러에 대한 짧은 제목만 반환합니다."""
    return translate_error(technical_error).title


def get_error_solution(technical_error: str) -> str:
    """에러 해결 방법만 반환합니다."""
    return translate_error(technical_error).solution


def is_error_recoverable(technical_error: str) -> bool:
    """에러가 재시도로 해결 가능한지 반환합니다."""
    return translate_error(technical_error).is_recoverable
