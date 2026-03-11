"""
User-friendly error message module

Converts technical error messages to user-friendly messages.
"""
from dataclasses import dataclass
from typing import Optional, Dict, List
import re


@dataclass
class UserFriendlyError:
    """User-friendly error information"""
    title: str              # Error title (short description)
    message: str            # Detailed error message
    solution: str           # How to resolve
    error_code: str         # Internal error code (for support)
    is_recoverable: bool    # Whether retry is possible


# Error pattern mapping (regex pattern -> user-friendly message)
# Note: Patterns are matched in order, so higher priority patterns should come first
ERROR_PATTERNS: List[Dict] = [
    # Cancellation related (highest priority - must match before other patterns)
    {
        "pattern": r"(CANCELLED|409.*cancelled)",
        "title": "Collection Cancelled",
        "message": "CANCELLED: Collection was cancelled by the server.",
        "solution": "The collection was cancelled by user or administrator. To start a new collection, please restart from the web platform.",
        "error_code": "CANCELLED",
        "is_recoverable": False,
    },
    # [2026-01-29] Cleanup in progress (upload blocked)
    {
        "pattern": r"(CLEANUP_IN_PROGRESS|cleanup.*progress)",
        "title": "Previous Data Cleanup in Progress",
        "message": "Previous data cleanup is in progress.",
        "solution": "Previous collection data is being deleted. Please wait for the cleanup to complete and try again. (Takes about 1-5 minutes)",
        "error_code": "CLEANUP_IN_PROGRESS",
        "is_recoverable": False,  # No auto-retry
    },

    # Network related
    {
        "pattern": r"(Cannot connect|ConnectionError|Connection refused|Unable to connect)",
        "title": "Server Connection Failed",
        "message": "Cannot connect to the server.",
        "solution": "1. Check your internet connection.\n2. Check if a firewall is blocking the connection.\n3. Verify the server URL is correct.",
        "error_code": "NET_CONN_FAIL",
        "is_recoverable": True,
    },
    {
        "pattern": r"(timeout|Timeout|timed out)",
        "title": "Connection Timeout",
        "message": "Timeout while waiting for server response.",
        "solution": "1. Network may be unstable. Please try again later.\n2. Large file uploads may take longer.",
        "error_code": "NET_TIMEOUT",
        "is_recoverable": True,
    },
    {
        "pattern": r"(SSL|TLS|certificate|CERTIFICATE)",
        "title": "Secure Connection Error",
        "message": "Error establishing secure connection (HTTPS).",
        "solution": "1. Check if system date and time are correct.\n2. Contact administrator about server certificate status.",
        "error_code": "NET_SSL_FAIL",
        "is_recoverable": False,
    },

    # Authentication related
    {
        "pattern": r"(401|Unauthorized|unauthorized)",
        "title": "Authentication Failed",
        "message": "Server authentication failed.",
        "solution": "1. Session token may have expired. Please get a new token.\n2. Check your login status on the web platform.",
        "error_code": "AUTH_FAIL",
        "is_recoverable": True,
    },
    {
        "pattern": r"(403|Forbidden|forbidden)",
        "title": "Access Denied",
        "message": "You do not have permission to perform this operation.",
        "solution": "1. Contact administrator about permission settings.\n2. Verify you are logged in with the correct account.",
        "error_code": "AUTH_PERM",
        "is_recoverable": False,
    },
    {
        "pattern": r"(expired|Expired)",
        "title": "Token Expired",
        "message": "Session token has expired.",
        "solution": "Please get a new token from the web platform.",
        "error_code": "AUTH_TOKEN_EXP",
        "is_recoverable": True,
    },
    {
        "pattern": r"(already used|already.*authenticated|token_already_used)",
        "title": "Token Already Used",
        "message": "This token has already been used.",
        "solution": "For security, tokens can only be used once. Please get a new token from the web platform.",
        "error_code": "AUTH_TOKEN_USED",
        "is_recoverable": True,
    },
    {
        "pattern": r"(token_revoked|revoked)",
        "title": "Token Revoked",
        "message": "This token has been revoked.",
        "solution": "The token was invalidated (e.g., due to cancellation). Please get a new token from the web platform.",
        "error_code": "AUTH_TOKEN_REVOKED",
        "is_recoverable": True,
    },
    {
        "pattern": r"(invalid_token|invalid.*token.*format)",
        "title": "Invalid Token",
        "message": "Token format is invalid.",
        "solution": "Please copy the token correctly from the web platform and try again.",
        "error_code": "AUTH_TOKEN_INVALID",
        "is_recoverable": True,
    },
    {
        "pattern": r"(ip_not_allowed|IP.*not.*allowed)",
        "title": "IP Address Not Allowed",
        "message": "This IP address is not authorized for collection.",
        "solution": "Contact the administrator to add your IP to the allowed list.",
        "error_code": "AUTH_IP_DENIED",
        "is_recoverable": False,
    },
    {
        "pattern": r"(denied by server|Authentication denied)",
        "title": "Authentication Denied",
        "message": "Server rejected the authentication request.",
        "solution": "The token may be invalid or expired. Please get a new token from the web platform.",
        "error_code": "AUTH_DENIED",
        "is_recoverable": True,
    },
    {
        "pattern": r"(Quota service not available|service.*not available)",
        "title": "Server Service Unavailable",
        "message": "Required server service is temporarily unavailable.",
        "solution": "Please try again in a few minutes. If the issue persists, contact the administrator.",
        "error_code": "SRV_SERVICE_UNAVAIL",
        "is_recoverable": True,
    },

    # File related
    {
        "pattern": r"(FileNotFoundError|No such file|not found)",
        "title": "File Not Found",
        "message": "The requested file does not exist.",
        "solution": "1. The file may have been deleted or moved.\n2. Check if antivirus software quarantined the file.",
        "error_code": "FILE_NOT_FOUND",
        "is_recoverable": False,
    },
    {
        "pattern": r"(PermissionError|Permission denied|Access.*denied)",
        "title": "File Access Denied",
        "message": "Cannot access the file.",
        "solution": "1. Run the program with administrator privileges.\n2. Check if another program is using the file.",
        "error_code": "FILE_PERM",
        "is_recoverable": True,
    },
    {
        "pattern": r"(disk.*full|No space left)",
        "title": "Disk Space Insufficient",
        "message": "Not enough storage space.",
        "solution": "1. Delete unnecessary files to free up space.\n2. Try using a different drive.",
        "error_code": "FILE_DISK_FULL",
        "is_recoverable": True,
    },

    # Collection related
    {
        "pattern": r"(MFT|\$MFT|Master File Table)",
        "title": "MFT Collection Error",
        "message": "Error occurred while collecting Master File Table (MFT).",
        "solution": "1. Run the program with administrator privileges.\n2. Verify the target drive uses NTFS file system.",
        "error_code": "COLLECT_MFT",
        "is_recoverable": True,
    },
    {
        "pattern": r"(Registry|HKEY_)",
        "title": "Registry Collection Error",
        "message": "Error occurred while collecting Windows Registry.",
        "solution": "1. Run the program with administrator privileges.\n2. Some registry keys may be protected.",
        "error_code": "COLLECT_REG",
        "is_recoverable": True,
    },

    # Encryption related
    {
        "pattern": r"(encrypt|Encrypt)",
        "title": "Encryption Error",
        "message": "Error occurred while encrypting file.",
        "solution": "1. Check if the file is corrupted.\n2. System memory may be insufficient.",
        "error_code": "CRYPTO_FAIL",
        "is_recoverable": True,
    },

    # Upload related
    {
        "pattern": r"(upload|Upload)",
        "title": "Upload Error",
        "message": "Error occurred while uploading file.",
        "solution": "1. Check your network connection.\n2. Verify file size does not exceed server limit.\n3. Please try again later.",
        "error_code": "UPLOAD_FAIL",
        "is_recoverable": True,
    },
    {
        "pattern": r"(413|Payload Too Large|too large)",
        "title": "File Size Exceeded",
        "message": "File size exceeds server limit.",
        "solution": "Large files require chunked upload. Please contact administrator.",
        "error_code": "UPLOAD_SIZE",
        "is_recoverable": False,
    },

    # Concurrent collection related (409 Conflict)
    {
        "pattern": r"(409|concurrent_collection|case_collection_in_progress|이미 다른 수집이 진행)",
        "title": "Collection Session Conflict",
        "message": "A collection is already in progress for this case, or a previous session was not properly closed.",
        "solution": "1. Go to the Web Platform → Case Detail page\n2. Click [Cancel Operation] to terminate the existing session\n3. Generate a new session token\n4. Enter the new token and authenticate again",
        "error_code": "COLLECT_CONFLICT",
        "is_recoverable": True,
    },

    # Server related
    {
        "pattern": r"(500|Internal Server Error)",
        "title": "Server Internal Error",
        "message": "An error occurred on the server.",
        "solution": "Please contact server administrator. You may also try again later.",
        "error_code": "SRV_INTERNAL",
        "is_recoverable": True,
    },
    {
        "pattern": r"(502|503|504|Service Unavailable)",
        "title": "Server Temporarily Unavailable",
        "message": "Server is temporarily unable to provide service.",
        "solution": "Server may be under maintenance. Please try again later.",
        "error_code": "SRV_UNAVAIL",
        "is_recoverable": True,
    },
]


def translate_error(technical_error: str) -> UserFriendlyError:
    """
    Converts technical error message to user-friendly message.

    Args:
        technical_error: Original technical error message

    Returns:
        UserFriendlyError object
    """
    if not technical_error:
        return UserFriendlyError(
            title="Unknown Error",
            message="An error occurred.",
            solution="Please restart the program or contact administrator.",
            error_code="UNKNOWN",
            is_recoverable=True,
        )

    # Find appropriate error message via pattern matching
    for error_info in ERROR_PATTERNS:
        if re.search(error_info["pattern"], technical_error, re.IGNORECASE):
            return UserFriendlyError(
                title=error_info["title"],
                message=error_info["message"],
                solution=error_info["solution"],
                error_code=error_info["error_code"],
                is_recoverable=error_info["is_recoverable"],
            )

    # Return default error if no pattern matches
    return UserFriendlyError(
        title="Error Occurred",
        message="An error occurred during the operation.",
        solution="Please check the logs or contact administrator for details.",
        error_code="GENERAL",
        is_recoverable=True,
    )


def format_error_for_display(error: UserFriendlyError, show_details: bool = True) -> str:
    """
    Formats error information as a display string.

    Args:
        error: UserFriendlyError object
        show_details: Whether to include detailed information

    Returns:
        Formatted error message string
    """
    lines = [
        f"Warning: {error.title}",
        "",
        error.message,
        "",
        "Solution:",
        error.solution,
    ]

    if show_details:
        lines.extend([
            "",
            f"Error Code: {error.error_code}",
        ])

        if error.is_recoverable:
            lines.append("This error may be resolved by retrying.")
        else:
            lines.append("This error requires configuration changes.")

    return "\n".join(lines)


def get_error_title(technical_error: str) -> str:
    """Returns only a short title for the error."""
    return translate_error(technical_error).title


def get_error_solution(technical_error: str) -> str:
    """Returns only the error solution."""
    return translate_error(technical_error).solution


def is_error_recoverable(technical_error: str) -> bool:
    """Returns whether the error can be resolved by retrying."""
    return translate_error(technical_error).is_recoverable
