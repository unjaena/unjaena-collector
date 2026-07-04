/*
  unJaena X-Ways X-Tension collector

  This X-Tension is intended to provide the same collection workflow as the
  public collector and EnCase collector path: analyst configuration, session
  authentication, collection profile loading, consent verification, profile
  matching, heartbeat validation, and raw-body upload to the backend.

  The source intentionally does not vendor the official XWF API package.
  Download the XWF C/C++ API from SourceForge and point xwf_api.local.props at
  the directory that contains the official X-Tension.h header.
*/

#include <windows.h>
#include <winhttp.h>

#include <stdint.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cwctype>
#include <exception>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

#if defined(__has_include)
#if __has_include("X-Tension.h")
#include "X-Tension.h"
#define UNJAENA_XWF_HAS_OFFICIAL_API 1
#endif
#endif

#ifndef UNJAENA_XWF_HAS_OFFICIAL_API
#define UNJAENA_XWF_HAS_OFFICIAL_API 0
#endif

#if !UNJAENA_XWF_HAS_OFFICIAL_API
#define XT_INIT_QUICKCHECK 0x00000020
#define XT_ACTION_RUN 0
#define XT_ACTION_RVS 1
#define XT_ACTION_DBC 4
#define XWF_ITEM_INFO_DELETION 4
#define XWF_ITEM_INFO_CLASSIFICATION 5
#define XWF_ITEM_INFO_CREATIONTIME 32
#define XWF_ITEM_INFO_MODIFICATIONTIME 33
#define XWF_ITEM_INFO_LASTACCESSTIME 34
#define XWF_ITEM_INFO_ENTRYMODIFICATIONTIME 35
#endif

#if UNJAENA_XWF_HAS_OFFICIAL_API
fptr_XWF_Read XWF_Read = NULL;
fptr_XWF_GetItemName XWF_GetItemName = NULL;
fptr_XWF_GetItemSize XWF_GetItemSize = NULL;
fptr_XWF_GetItemInformation XWF_GetItemInformation = NULL;
fptr_XWF_GetItemType XWF_GetItemType = NULL;
fptr_XWF_GetItemParent XWF_GetItemParent = NULL;
fptr_XWF_GetReportTableAssocs XWF_GetReportTableAssocs = NULL;
fptr_XWF_GetComment XWF_GetComment = NULL;
fptr_XWF_OutputMessage XWF_OutputMessage = NULL;
fptr_XWF_ShowProgress XWF_ShowProgress = NULL;
fptr_XWF_SetProgressDescription XWF_SetProgressDescription = NULL;
fptr_XWF_SetProgressPercentage XWF_SetProgressPercentage = NULL;
fptr_XWF_ShouldStop XWF_ShouldStop = NULL;
fptr_XWF_HideProgress XWF_HideProgress = NULL;
fptr_XWF_OpenItem XWF_OpenItem = NULL;
fptr_XWF_Close XWF_Close = NULL;

static void* ResolveXwfFunction(const char* name, LONG* missing_count) {
    HMODULE host = GetModuleHandleW(NULL);
    void* fn = host == NULL ? NULL : reinterpret_cast<void*>(GetProcAddress(host, name));
    if (fn == NULL && missing_count != NULL) {
        ++(*missing_count);
    }
    return fn;
}

LONG __stdcall XT_RetrieveFunctionPointers() {
    LONG missing = 0;
#define UNJAENA_LOAD_XWF_FN(name) \
    name = reinterpret_cast<fptr_##name>(ResolveXwfFunction(#name, &missing))

    UNJAENA_LOAD_XWF_FN(XWF_Read);
    UNJAENA_LOAD_XWF_FN(XWF_GetItemName);
    UNJAENA_LOAD_XWF_FN(XWF_GetItemSize);
    UNJAENA_LOAD_XWF_FN(XWF_GetItemInformation);
    UNJAENA_LOAD_XWF_FN(XWF_GetItemType);
    UNJAENA_LOAD_XWF_FN(XWF_GetItemParent);
    UNJAENA_LOAD_XWF_FN(XWF_GetReportTableAssocs);
    UNJAENA_LOAD_XWF_FN(XWF_GetComment);
    UNJAENA_LOAD_XWF_FN(XWF_OutputMessage);
    UNJAENA_LOAD_XWF_FN(XWF_ShowProgress);
    UNJAENA_LOAD_XWF_FN(XWF_SetProgressDescription);
    UNJAENA_LOAD_XWF_FN(XWF_SetProgressPercentage);
    UNJAENA_LOAD_XWF_FN(XWF_ShouldStop);
    UNJAENA_LOAD_XWF_FN(XWF_HideProgress);
    UNJAENA_LOAD_XWF_FN(XWF_OpenItem);
    UNJAENA_LOAD_XWF_FN(XWF_Close);

#undef UNJAENA_LOAD_XWF_FN
    return missing;
}

const char* getMissingFunctions() {
    return "unJaena resolves only the XWF functions used by this collector.";
}
#endif

namespace unjaena_xwf {

static const wchar_t* kXtParamPrefix = L"XTParam:UNJAENA:";
static const DWORD kReadChunkBytes = 1024 * 1024;
static const DWORD kUploadHeartbeatItemInterval = 50000;
static const ULONGLONG kUploadHeartbeatMs = 5ULL * 60ULL * 1000ULL;
static const uint64_t kMaxDirectUploadBytes = 1000000000ULL;

#define IDC_HOST_EDIT 1001
#define IDC_PORT_EDIT 1002
#define IDC_SSL_CHECK 1003
#define IDC_TOKEN_EDIT 1004
#define IDC_MAX_UPLOADS_EDIT 1005
#define IDC_CONSENT_CHECK 1006
#define IDC_OK_BUTTON 1007
#define IDC_CANCEL_BUTTON 1008

struct Config {
    std::wstring server_host;
    INTERNET_PORT server_port;
    bool use_ssl;
    std::wstring session_token;
    std::wstring session_id;
    std::wstring collection_token;
    std::wstring case_id;
    std::wstring profile_id;
    std::wstring operator_name;
    uint64_t max_uploads;
    bool collection_consent_accepted;
    Config()
        : server_host(L"app.unjaena.com"),
          server_port(443),
          use_ssl(true),
          operator_name(L"X-Ways operator"),
          max_uploads(0),
          collection_consent_accepted(false) {}
};

struct ProfileTarget {
    std::string artifact_type;
    std::string kind;
    std::vector<std::string> patterns;
    uint64_t max_bytes;
};

struct ItemInfo {
    LONG item_id;
    HANDLE item;
    uint64_t size;
    std::wstring raw_path;
    std::wstring file_name;
    std::string normalized_path;
    std::string normalized_name;
    std::string extension;
    std::string file_type;
};

struct HttpResponse {
    bool ok;
    DWORD status;
    std::string body;
    std::string error;
    HttpResponse() : ok(false), status(0) {}
};

static Config g_config;
static std::vector<ProfileTarget> g_profile_targets;
static HANDLE g_volume = NULL;
static HWND g_main_window = NULL;
static DWORD g_operation_type = XT_ACTION_RUN;
static HINSTANCE g_module_instance = NULL;
static bool g_ready = false;
static bool g_cancelled_by_user = false;
static uint64_t g_processed_count = 0;
static uint64_t g_uploaded_count = 0;
static uint64_t g_skipped_count = 0;
static uint64_t g_failed_count = 0;
static uint64_t g_skipped_no_profile_match = 0;
static uint64_t g_skipped_zero_byte = 0;
static uint64_t g_skipped_directory = 0;
static uint64_t g_skipped_too_large = 0;
static ULONGLONG g_last_heartbeat_ms = 0;
static uint64_t g_last_heartbeat_item = 0;

static std::string Utf8FromWide(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, NULL, 0, NULL, NULL);
    if (needed <= 1) {
        return std::string();
    }
    std::string output(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &output[0], needed, NULL, NULL);
    return output;
}

static std::wstring WideFromUtf8(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }
    int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, NULL, 0);
    if (needed <= 1) {
        return std::wstring();
    }
    std::wstring output(static_cast<size_t>(needed - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &output[0], needed);
    return output;
}

static HINSTANCE ModuleInstance() {
    if (g_module_instance != NULL) {
        return g_module_instance;
    }
    HMODULE module = NULL;
    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&ModuleInstance),
            &module)) {
        g_module_instance = module;
        return g_module_instance;
    }
    return GetModuleHandleW(NULL);
}

static std::string LowerAscii(std::string value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

static std::wstring LowerWide(std::wstring value) {
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return value;
}

static std::wstring BaseName(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

static std::string NormalizePath(const std::wstring& value) {
    std::string path = LowerAscii(Utf8FromWide(value));
    std::replace(path.begin(), path.end(), '\\', '/');
    while (path.find("//") != std::string::npos) {
        size_t pos = path.find("//");
        path.replace(pos, 2, "/");
    }
    return path;
}

static std::string ExtensionFromName(const std::string& name) {
    size_t dot = name.find_last_of('.');
    if (dot == std::string::npos || dot + 1 >= name.size()) {
        return std::string();
    }
    return name.substr(dot + 1);
}

static std::string JsonEscape(const std::string& value) {
    std::ostringstream out;
    for (size_t i = 0; i < value.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(value[i]);
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) {
                    char buf[7];
                    wsprintfA(buf, "\\u%04x", ch);
                    out << buf;
                } else {
                    out << value[i];
                }
        }
    }
    return out.str();
}

static std::string JsonStringOrNull(const std::string& value) {
    return value.empty() ? "null" : "\"" + JsonEscape(value) + "\"";
}

static std::string CompactError(const std::string& body) {
    std::string compact = body;
    for (size_t i = 0; i < compact.size(); ++i) {
        if (compact[i] == '\r' || compact[i] == '\n' || compact[i] == '\t') {
            compact[i] = ' ';
        }
    }
    while (compact.find("  ") != std::string::npos) {
        size_t pos = compact.find("  ");
        compact.replace(pos, 2, " ");
    }
    if (compact.size() > 600) {
        compact.resize(600);
    }
    return compact;
}

static std::wstring DiagnosticLogPath() {
    wchar_t temp_path[MAX_PATH] = {0};
    DWORD len = GetTempPathW(static_cast<DWORD>(sizeof(temp_path) / sizeof(temp_path[0])), temp_path);
    if (len == 0 || len >= static_cast<DWORD>(sizeof(temp_path) / sizeof(temp_path[0]))) {
        return L"UnjaenaXwfCollector.log";
    }
    std::wstring path(temp_path);
    if (!path.empty() && path[path.size() - 1] != L'\\' && path[path.size() - 1] != L'/') {
        path += L"\\";
    }
    path += L"UnjaenaXwfCollector.log";
    return path;
}

static void AppendDiagnosticLog(const std::wstring& message) {
    HANDLE file = CreateFileW(
        DiagnosticLogPath().c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    SYSTEMTIME now = {};
    GetLocalTime(&now);
    wchar_t prefix[96] = {0};
    wsprintfW(
        prefix,
        L"%04u-%02u-%02u %02u:%02u:%02u.%03u ",
        static_cast<unsigned>(now.wYear),
        static_cast<unsigned>(now.wMonth),
        static_cast<unsigned>(now.wDay),
        static_cast<unsigned>(now.wHour),
        static_cast<unsigned>(now.wMinute),
        static_cast<unsigned>(now.wSecond),
        static_cast<unsigned>(now.wMilliseconds));
    std::wstring line(prefix);
    line += message;
    line += L"\r\n";

    int bytes_needed = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, NULL, 0, NULL, NULL);
    if (bytes_needed > 1) {
        std::string utf8(static_cast<size_t>(bytes_needed - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, &utf8[0], bytes_needed, NULL, NULL);
        DWORD written = 0;
        WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, NULL);
    }
    CloseHandle(file);
}

static void OutputMessage(const std::wstring& message) {
    AppendDiagnosticLog(message);
#if UNJAENA_XWF_HAS_OFFICIAL_API
    if (XWF_OutputMessage != NULL) {
        XWF_OutputMessage(message.c_str(), 0);
        return;
    }
#endif
    OutputDebugStringW(message.c_str());
    OutputDebugStringW(L"\n");
}

static void OutputMessageUtf8(const std::string& message) {
    OutputMessage(WideFromUtf8(message));
}

static uint64_t ParseUint64(const std::wstring& value, uint64_t fallback) {
    if (value.empty()) {
        return fallback;
    }
    wchar_t* end = NULL;
    unsigned long long parsed = wcstoull(value.c_str(), &end, 10);
    if (end == value.c_str()) {
        return fallback;
    }
    return static_cast<uint64_t>(parsed);
}

static std::wstring GetWindowTextWide(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    std::wstring value(static_cast<size_t>(len), L'\0');
    if (len > 0) {
        GetWindowTextW(hwnd, &value[0], len + 1);
    }
    return value;
}

struct DialogState {
    Config* config;
    HWND host_edit;
    HWND port_edit;
    HWND ssl_check;
    HWND token_edit;
    HWND max_uploads_edit;
    HWND consent_check;
    bool accepted;
    DialogState() : config(NULL), host_edit(NULL), port_edit(NULL), ssl_check(NULL), token_edit(NULL), max_uploads_edit(NULL), consent_check(NULL), accepted(false) {}
};

static HWND MakeControl(HWND parent, const wchar_t* klass, const wchar_t* text, DWORD style, int x, int y, int w, int h, int id) {
    return CreateWindowExW(
        0,
        klass,
        text,
        WS_CHILD | WS_VISIBLE | style,
        x,
        y,
        w,
        h,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ModuleInstance(),
        NULL);
}

static LRESULT CALLBACK ConfigWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    DialogState* state = reinterpret_cast<DialogState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
        case WM_CREATE: {
            CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = reinterpret_cast<DialogState*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));

            HFONT font = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
            MakeControl(hwnd, L"STATIC", L"Server host", 0, 16, 18, 100, 22, 0);
            state->host_edit = MakeControl(hwnd, L"EDIT", state->config->server_host.c_str(), WS_BORDER | ES_AUTOHSCROLL, 130, 16, 260, 22, IDC_HOST_EDIT);
            MakeControl(hwnd, L"STATIC", L"Server port", 0, 16, 50, 100, 22, 0);
            wchar_t port_text[16] = {0};
            wsprintfW(port_text, L"%u", static_cast<unsigned>(state->config->server_port));
            state->port_edit = MakeControl(hwnd, L"EDIT", port_text, WS_BORDER | ES_NUMBER | ES_AUTOHSCROLL, 130, 50, 100, 22, IDC_PORT_EDIT);
            state->ssl_check = MakeControl(hwnd, L"BUTTON", L"Use SSL", BS_AUTOCHECKBOX, 250, 50, 140, 22, IDC_SSL_CHECK);
            SendMessageW(state->ssl_check, BM_SETCHECK, state->config->use_ssl ? BST_CHECKED : BST_UNCHECKED, 0);

            MakeControl(hwnd, L"STATIC", L"Session token", 0, 16, 84, 100, 22, 0);
            state->token_edit = MakeControl(hwnd, L"EDIT", state->config->session_token.c_str(), WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, 130, 84, 260, 22, IDC_TOKEN_EDIT);
            MakeControl(hwnd, L"STATIC", L"Max uploads", 0, 16, 118, 100, 22, 0);
            wchar_t max_text[32] = {0};
            wsprintfW(max_text, L"%llu", static_cast<unsigned long long>(state->config->max_uploads));
            state->max_uploads_edit = MakeControl(hwnd, L"EDIT", max_text, WS_BORDER | ES_NUMBER | ES_AUTOHSCROLL, 130, 118, 100, 22, IDC_MAX_UPLOADS_EDIT);
            state->consent_check = MakeControl(hwnd, L"BUTTON", L"I confirm I have legal authority and consent to collect/upload this evidence.", BS_AUTOCHECKBOX | BS_MULTILINE, 16, 152, 380, 42, IDC_CONSENT_CHECK);
            SendMessageW(state->consent_check, BM_SETCHECK, state->config->collection_consent_accepted ? BST_CHECKED : BST_UNCHECKED, 0);

            MakeControl(hwnd, L"BUTTON", L"Start", BS_DEFPUSHBUTTON, 210, 210, 80, 28, IDC_OK_BUTTON);
            MakeControl(hwnd, L"BUTTON", L"Cancel", 0, 310, 210, 80, 28, IDC_CANCEL_BUTTON);

            HWND child = GetWindow(hwnd, GW_CHILD);
            while (child != NULL) {
                SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
                child = GetWindow(child, GW_HWNDNEXT);
            }
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            if (id == IDC_CANCEL_BUTTON) {
                DestroyWindow(hwnd);
                return 0;
            }
            if (id == IDC_OK_BUTTON && state != NULL && state->config != NULL) {
                Config& cfg = *state->config;
                cfg.server_host = GetWindowTextWide(state->host_edit);
                cfg.server_port = static_cast<INTERNET_PORT>(ParseUint64(GetWindowTextWide(state->port_edit), 443));
                cfg.use_ssl = SendMessageW(state->ssl_check, BM_GETCHECK, 0, 0) == BST_CHECKED;
                cfg.session_token = GetWindowTextWide(state->token_edit);
                cfg.max_uploads = ParseUint64(GetWindowTextWide(state->max_uploads_edit), 0);
                cfg.collection_consent_accepted = SendMessageW(state->consent_check, BM_GETCHECK, 0, 0) == BST_CHECKED;

                if (cfg.server_host.empty() || cfg.session_token.find(L":") == std::wstring::npos) {
                    MessageBoxW(hwnd, L"Enter server host and the full session-id:secret token from the case page.", L"unJaena X-Ways Collector", MB_OK | MB_ICONWARNING);
                    return 0;
                }
                if (!cfg.collection_consent_accepted) {
                    MessageBoxW(hwnd, L"Collection consent is required before upload.", L"unJaena X-Ways Collector", MB_OK | MB_ICONWARNING);
                    return 0;
                }
                state->accepted = true;
                DestroyWindow(hwnd);
                return 0;
            }
            break;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static bool ShowConfigDialog(HWND parent, Config* config) {
    DialogState state;
    state.config = config;

    WNDCLASSW wc = {};
    wc.lpfnWndProc = ConfigWndProc;
    wc.hInstance = ModuleInstance();
    wc.lpszClassName = L"UnjaenaXwfCollectorConfig";
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    ATOM registered = RegisterClassW(&wc);
    DWORD register_error = registered == 0 ? GetLastError() : ERROR_SUCCESS;
    if (registered == 0 && register_error != ERROR_CLASS_ALREADY_EXISTS) {
        OutputMessage(L"XWF config dialog RegisterClassW failed.");
        return false;
    }

    HWND hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        wc.lpszClassName,
        L"unJaena X-Ways Collector",
        WS_CAPTION | WS_SYSMENU | WS_POPUP,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        430,
        290,
        parent,
        NULL,
        wc.hInstance,
        &state);
    if (hwnd == NULL) {
        OutputMessage(L"XWF config dialog CreateWindowExW failed.");
        if (registered != 0) {
            UnregisterClassW(wc.lpszClassName, wc.hInstance);
        }
        return false;
    }

    if (parent != NULL) {
        EnableWindow(parent, FALSE);
    }
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (IsWindow(hwnd)) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (!IsWindow(hwnd)) {
                break;
            }
            if (!IsDialogMessageW(hwnd, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if (IsWindow(hwnd)) {
            WaitMessage();
        }
    }
    if (parent != NULL) {
        EnableWindow(parent, TRUE);
        SetForegroundWindow(parent);
    }
    if (registered != 0) {
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
    }
    return state.accepted;
}

static std::wstring ExtractXtParamPayload(const std::wstring& command_line) {
    size_t pos = command_line.find(kXtParamPrefix);
    if (pos == std::wstring::npos) {
        return std::wstring();
    }
    pos += wcslen(kXtParamPrefix);
    size_t end = pos;
    bool quoted = pos < command_line.size() && command_line[pos] == L'"';
    if (quoted) {
        ++pos;
        end = pos;
    }
    while (end < command_line.size()) {
        wchar_t ch = command_line[end];
        if ((quoted && ch == L'"') || (!quoted && (ch == L' ' || ch == L'\t'))) {
            break;
        }
        ++end;
    }
    return command_line.substr(pos, end - pos);
}

static std::vector<std::wstring> SplitWide(const std::wstring& value, wchar_t delimiter) {
    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start <= value.size()) {
        size_t end = value.find(delimiter, start);
        std::wstring part = value.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
        if (!part.empty()) {
            parts.push_back(part);
        }
        if (end == std::wstring::npos) {
            break;
        }
        start = end + 1;
    }
    return parts;
}

static void ApplyConfigToken(Config* config, const std::wstring& token) {
    size_t equal = token.find(L'=');
    if (equal == std::wstring::npos) {
        return;
    }
    std::wstring key = LowerWide(token.substr(0, equal));
    std::wstring value = token.substr(equal + 1);
    if (key == L"host" || key == L"server_host") {
        config->server_host = value;
    } else if (key == L"port" || key == L"server_port") {
        config->server_port = static_cast<INTERNET_PORT>(ParseUint64(value, config->server_port));
    } else if (key == L"ssl" || key == L"use_ssl") {
        std::wstring lowered = LowerWide(value);
        config->use_ssl = lowered == L"true" || lowered == L"1" || lowered == L"yes";
    } else if (key == L"token" || key == L"session_token") {
        config->session_token = value;
    } else if (key == L"max_uploads") {
        config->max_uploads = ParseUint64(value, 0);
    } else if (key == L"consent") {
        std::wstring lowered = LowerWide(value);
        config->collection_consent_accepted = lowered == L"true" || lowered == L"1" || lowered == L"yes";
    }
}

static bool ApplyCommandLineConfig(Config* config) {
    std::wstring payload = ExtractXtParamPayload(GetCommandLineW());
    if (payload.empty()) {
        return false;
    }
    std::vector<std::wstring> tokens = SplitWide(payload, L';');
    for (size_t i = 0; i < tokens.size(); ++i) {
        ApplyConfigToken(config, tokens[i]);
    }
    return true;
}

static std::string JsonString(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return std::string();
    }
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) {
        return std::string();
    }
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) {
        return std::string();
    }
    std::string output;
    bool escaped = false;
    for (size_t i = pos + 1; i < json.size(); ++i) {
        char ch = json[i];
        if (escaped) {
            switch (ch) {
                case '"': case '\\': case '/': output.push_back(ch); break;
                case 'b': output.push_back('\b'); break;
                case 'f': output.push_back('\f'); break;
                case 'n': output.push_back('\n'); break;
                case 'r': output.push_back('\r'); break;
                case 't': output.push_back('\t'); break;
                default: output.push_back(ch); break;
            }
            escaped = false;
        } else if (ch == '\\') {
            escaped = true;
        } else if (ch == '"') {
            break;
        } else {
            output.push_back(ch);
        }
    }
    return output;
}

static uint64_t JsonNumber(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return 0;
    }
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) {
        return 0;
    }
    ++pos;
    while (pos < json.size() && isspace(static_cast<unsigned char>(json[pos]))) {
        ++pos;
    }
    size_t start = pos;
    while (pos < json.size() && isdigit(static_cast<unsigned char>(json[pos]))) {
        ++pos;
    }
    if (start == pos) {
        return 0;
    }
    return static_cast<uint64_t>(_strtoui64(json.substr(start, pos - start).c_str(), NULL, 10));
}

static bool JsonBool(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) {
        return false;
    }
    ++pos;
    while (pos < json.size() && isspace(static_cast<unsigned char>(json[pos]))) {
        ++pos;
    }
    return json.compare(pos, 4, "true") == 0;
}

static std::string JsonArrayRaw(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return std::string();
    }
    pos = json.find('[', pos + needle.size());
    if (pos == std::string::npos) {
        return std::string();
    }
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (size_t i = pos; i < json.size(); ++i) {
        char ch = json[i];
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }
        if (ch == '"') {
            in_string = true;
        } else if (ch == '[') {
            ++depth;
        } else if (ch == ']') {
            --depth;
            if (depth == 0) {
                return json.substr(pos, i - pos + 1);
            }
        }
    }
    return std::string();
}

static std::vector<std::string> JsonStringArray(const std::string& json, const std::string& key) {
    std::vector<std::string> values;
    std::string raw = JsonArrayRaw(json, key);
    bool in_string = false;
    bool escaped = false;
    std::string current;
    for (size_t i = 0; i < raw.size(); ++i) {
        char ch = raw[i];
        if (!in_string) {
            if (ch == '"') {
                in_string = true;
                current.clear();
            }
            continue;
        }
        if (escaped) {
            current.push_back(ch);
            escaped = false;
        } else if (ch == '\\') {
            escaped = true;
        } else if (ch == '"') {
            values.push_back(current);
            in_string = false;
        } else {
            current.push_back(ch);
        }
    }
    return values;
}

static std::vector<std::string> JsonObjectsInArray(const std::string& raw_array) {
    std::vector<std::string> objects;
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    size_t start = std::string::npos;
    for (size_t i = 0; i < raw_array.size(); ++i) {
        char ch = raw_array[i];
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }
        if (ch == '"') {
            in_string = true;
        } else if (ch == '{') {
            if (depth == 0) {
                start = i;
            }
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0 && start != std::string::npos) {
                objects.push_back(raw_array.substr(start, i - start + 1));
                start = std::string::npos;
            }
        }
    }
    return objects;
}

static std::wstring UrlPathFromApiPath(const Config& cfg, const std::string& value) {
    if (value.empty()) {
        return L"/";
    }
    if (value.compare(0, 7, "http://") == 0 || value.compare(0, 8, "https://") == 0) {
        std::wstring wide = WideFromUtf8(value);
        URL_COMPONENTSW parts = {};
        wchar_t host[512] = {0};
        wchar_t path[4096] = {0};
        wchar_t extra[4096] = {0};
        parts.dwStructSize = sizeof(parts);
        parts.lpszHostName = host;
        parts.dwHostNameLength = sizeof(host) / sizeof(host[0]);
        parts.lpszUrlPath = path;
        parts.dwUrlPathLength = sizeof(path) / sizeof(path[0]);
        parts.lpszExtraInfo = extra;
        parts.dwExtraInfoLength = sizeof(extra) / sizeof(extra[0]);
        if (WinHttpCrackUrl(wide.c_str(), 0, 0, &parts)) {
            bool actual_ssl = parts.nScheme == INTERNET_SCHEME_HTTPS;
            INTERNET_PORT actual_port = parts.nPort;
            INTERNET_PORT expected_port = cfg.server_port == 0 ? static_cast<INTERNET_PORT>(cfg.use_ssl ? 443 : 80) : cfg.server_port;
            if (actual_ssl != cfg.use_ssl || _wcsicmp(host, cfg.server_host.c_str()) != 0 || actual_port != expected_port) {
                return L"/__invalid_cross_host_collector_url__";
            }
            std::wstring result(path);
            result += extra;
            return result.empty() ? L"/" : result;
        }
    }
    return WideFromUtf8(value[0] == '/' ? value : "/" + value);
}

static HttpResponse ReadHttpResponse(HINTERNET request) {
    HttpResponse response;
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status,
        &status_size,
        WINHTTP_NO_HEADER_INDEX);
    response.status = status;
    response.ok = status >= 200 && status < 300;

    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available) || available == 0) {
            break;
        }
        std::vector<char> buffer(static_cast<size_t>(available) + 1, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, &buffer[0], available, &read)) {
            break;
        }
        response.body.append(&buffer[0], &buffer[0] + read);
    }
    if (!response.ok) {
        response.error = CompactError(response.body);
        if (response.error.empty()) {
            response.error = "HTTP request failed";
        }
    }
    return response;
}

static std::wstring BuildHeaders(const std::wstring& content_type, const std::string& ticket, const std::string& session_id, const std::string& collection_token) {
    std::wstring headers = L"Accept: application/json\r\n";
    if (!content_type.empty()) {
        headers += L"Content-Type: " + content_type + L"\r\n";
    }
    if (!ticket.empty()) {
        headers += L"X-XWays-Upload-Ticket: " + WideFromUtf8(ticket) + L"\r\n";
    }
    if (!session_id.empty()) {
        headers += L"X-Session-ID: " + WideFromUtf8(session_id) + L"\r\n";
    }
    if (!collection_token.empty()) {
        headers += L"X-Collection-Token: " + WideFromUtf8(collection_token) + L"\r\n";
    }
    return headers;
}

static HINTERNET OpenHttpSession() {
    return WinHttpOpen(
        L"unJaena-XWays-XTension/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
}

static HttpResponse HttpRequest(
    const Config& cfg,
    const wchar_t* method,
    const std::string& path,
    const std::string& body,
    const std::wstring& content_type,
    const std::string& ticket = std::string(),
    const std::string& session_id = std::string(),
    const std::string& collection_token = std::string()) {
    HttpResponse response;
    HINTERNET session = OpenHttpSession();
    if (session == NULL) {
        response.error = "WinHttpOpen failed";
        return response;
    }
    HINTERNET connect = WinHttpConnect(session, cfg.server_host.c_str(), cfg.server_port, 0);
    if (connect == NULL) {
        response.error = "WinHttpConnect failed";
        WinHttpCloseHandle(session);
        return response;
    }
    std::wstring request_path = UrlPathFromApiPath(cfg, path);
    DWORD flags = cfg.use_ssl ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, method, request_path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (request == NULL) {
        response.error = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return response;
    }
    DWORD timeout = 120000;
    WinHttpSetTimeouts(request, timeout, timeout, timeout, timeout);
    std::wstring headers = BuildHeaders(content_type, ticket, session_id, collection_token);
    BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);
    if (!sent || !WinHttpReceiveResponse(request, NULL)) {
        response.error = "WinHTTP request failed";
    } else {
        response = ReadHttpResponse(request);
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return response;
}

static HttpResponse HttpPutItem(const Config& cfg, const std::string& path, HANDLE item, uint64_t size, const std::string& ticket) {
    HttpResponse response;
#if UNJAENA_XWF_HAS_OFFICIAL_API
    if (item == NULL || XWF_Read == NULL) {
        response.error = "XWF_Read unavailable";
        return response;
    }
    if (size > 0xFFFFFFFFULL) {
        response.error = "file is too large for one WinHTTP raw-body upload";
        return response;
    }
    HINTERNET session = OpenHttpSession();
    if (session == NULL) {
        response.error = "WinHttpOpen failed";
        return response;
    }
    HINTERNET connect = WinHttpConnect(session, cfg.server_host.c_str(), cfg.server_port, 0);
    if (connect == NULL) {
        response.error = "WinHttpConnect failed";
        WinHttpCloseHandle(session);
        return response;
    }
    std::wstring request_path = UrlPathFromApiPath(cfg, path);
    DWORD flags = cfg.use_ssl ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"PUT", request_path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (request == NULL) {
        response.error = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return response;
    }
    DWORD timeout = 120000;
    if (size > 0) {
        uint64_t estimated_ms = ((size / (256ULL * 1024ULL)) + 300ULL) * 1000ULL;
        if (estimated_ms > timeout) {
            timeout = static_cast<DWORD>(estimated_ms > 30ULL * 60ULL * 1000ULL ? 30ULL * 60ULL * 1000ULL : estimated_ms);
        }
    }
    WinHttpSetTimeouts(request, timeout, timeout, timeout, timeout);
    std::wstring headers = BuildHeaders(L"application/octet-stream", ticket, std::string(), std::string());
    BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        WINHTTP_NO_REQUEST_DATA,
        0,
        static_cast<DWORD>(size),
        0);
    if (!sent) {
        response.error = "WinHttpSendRequest failed";
    } else {
        std::vector<BYTE> buffer(kReadChunkBytes);
        uint64_t offset = 0;
        bool write_ok = true;
        while (offset < size) {
            if (XWF_ShouldStop != NULL && XWF_ShouldStop()) {
                write_ok = false;
                response.error = "X-Ways stop requested";
                break;
            }
            uint64_t remaining = size - offset;
            DWORD request_bytes = remaining < buffer.size() ? static_cast<DWORD>(remaining) : static_cast<DWORD>(buffer.size());
            DWORD read = XWF_Read(item, static_cast<INT64>(offset), &buffer[0], request_bytes);
            if (read == 0) {
                write_ok = false;
                response.error = "XWF_Read returned zero bytes";
                break;
            }
            DWORD written = 0;
            if (!WinHttpWriteData(request, &buffer[0], read, &written) || written != read) {
                write_ok = false;
                response.error = "WinHttpWriteData failed";
                break;
            }
            offset += read;
        }
        if (write_ok && WinHttpReceiveResponse(request, NULL)) {
            response = ReadHttpResponse(request);
        } else if (write_ok) {
            response.error = "WinHttpReceiveResponse failed";
        }
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
#else
    UNREFERENCED_PARAMETER(cfg);
    UNREFERENCED_PARAMETER(path);
    UNREFERENCED_PARAMETER(item);
    UNREFERENCED_PARAMETER(size);
    UNREFERENCED_PARAMETER(ticket);
    response.error = "official XWF API header not available";
#endif
    return response;
}

static bool WildcardMatch(const std::string& text, const std::string& pattern) {
    size_t ti = 0;
    size_t pi = 0;
    size_t star = std::string::npos;
    size_t match = 0;
    while (ti < text.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' || pattern[pi] == text[ti])) {
            ++ti;
            ++pi;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star = pi++;
            match = ti;
        } else if (star != std::string::npos) {
            pi = star + 1;
            ti = ++match;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') {
        ++pi;
    }
    return pi == pattern.size();
}

static std::vector<std::string> PatternVariants(const std::string& pattern, const std::string& extension) {
    std::vector<std::string> variants;
    std::string p = LowerAscii(pattern);
    std::replace(p.begin(), p.end(), '\\', '/');
    variants.push_back(p);
    if (!extension.empty() && p == "*." + extension) {
        variants.push_back("*" + extension);
    }
    return variants;
}

static bool IsSourceFileTarget(const ProfileTarget& target) {
    std::string kind = LowerAscii(target.kind);
    return kind == "source_file" || kind == "source_upload" || kind == "evidence_source";
}

static std::string MatchProfileArtifact(const ItemInfo& item) {
    for (size_t i = 0; i < g_profile_targets.size(); ++i) {
        const ProfileTarget& target = g_profile_targets[i];
        if (target.artifact_type.empty() || IsSourceFileTarget(target)) {
            continue;
        }
        if (target.max_bytes > 0 && item.size > target.max_bytes) {
            continue;
        }
        for (size_t j = 0; j < target.patterns.size(); ++j) {
            std::vector<std::string> variants = PatternVariants(target.patterns[j], item.extension);
            for (size_t k = 0; k < variants.size(); ++k) {
                const std::string& pattern = variants[k];
                bool path_pattern = pattern.find('/') != std::string::npos || pattern.find(':') != std::string::npos;
                const std::string& candidate = path_pattern ? item.normalized_path : item.normalized_name;
                if (WildcardMatch(candidate, pattern)) {
                    return target.artifact_type;
                }
                if (path_pattern && !pattern.empty() && pattern[0] != '*' && WildcardMatch(item.normalized_path, "*" + pattern)) {
                    return target.artifact_type;
                }
            }
        }
    }
    return std::string();
}

static bool ParseCollectionProfile(const std::string& body) {
    g_config.profile_id = WideFromUtf8(JsonString(body, "profile_id"));
    g_profile_targets.clear();
    std::string targets_raw = JsonArrayRaw(body, "targets");
    std::vector<std::string> objects = JsonObjectsInArray(targets_raw);
    for (size_t i = 0; i < objects.size(); ++i) {
        ProfileTarget target;
        target.artifact_type = JsonString(objects[i], "artifact_type");
        target.kind = JsonString(objects[i], "kind");
        target.patterns = JsonStringArray(objects[i], "patterns");
        target.max_bytes = JsonNumber(objects[i], "max_bytes");
        if (!target.artifact_type.empty() && !target.patterns.empty()) {
            g_profile_targets.push_back(target);
        }
    }
    return !g_config.profile_id.empty() && !g_profile_targets.empty();
}

static std::string BuildHardwareId() {
    wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(computer_name, &len)) {
        return "xways-unknown";
    }
    return "xways-" + Utf8FromWide(computer_name);
}

static bool Authenticate() {
    std::string body = "{"
        "\"session_token\":\"" + JsonEscape(Utf8FromWide(g_config.session_token)) + "\","
        "\"hardware_id\":\"" + JsonEscape(BuildHardwareId()) + "\","
        "\"client_info\":{\"client\":\"xways_xtension\",\"mode\":\"native_xwf\",\"version\":\"1.0.0\"}"
        "}";
    HttpResponse response = HttpRequest(g_config, L"POST", "/api/v1/collector/xways/authenticate", body, L"application/json");
    if (!response.ok) {
        OutputMessageUtf8("XWF authentication failed: " + response.error);
        return false;
    }
    g_config.session_id = WideFromUtf8(JsonString(response.body, "session_id"));
    g_config.collection_token = WideFromUtf8(JsonString(response.body, "collection_token"));
    g_config.case_id = WideFromUtf8(JsonString(response.body, "case_id"));
    if (g_config.session_id.empty() || g_config.collection_token.empty() || g_config.case_id.empty()) {
        OutputMessage(L"XWF authentication response is missing session_id, collection_token, or case_id.");
        return false;
    }
    return true;
}

static bool LoadCollectionProfile() {
    HttpResponse response = HttpRequest(
        g_config,
        L"POST",
        "/api/v1/collector/collection/profile",
        "{}",
        L"application/json",
        std::string(),
        Utf8FromWide(g_config.session_id),
        Utf8FromWide(g_config.collection_token));
    if (!response.ok) {
        OutputMessageUtf8("XWF collection profile load failed: " + response.error);
        return false;
    }
    if (!ParseCollectionProfile(response.body)) {
        OutputMessage(L"XWF collection profile response is missing profile_id or authorized targets.");
        return false;
    }
    return true;
}

static bool ValidateSession() {
    std::string body = "{"
        "\"session_id\":\"" + JsonEscape(Utf8FromWide(g_config.session_id)) + "\","
        "\"collection_token\":\"" + JsonEscape(Utf8FromWide(g_config.collection_token)) + "\","
        "\"profile_id\":" + JsonStringOrNull(Utf8FromWide(g_config.profile_id)) +
        "}";
    HttpResponse response = HttpRequest(g_config, L"POST", "/api/v1/collector/validate-session", body, L"application/json");
    if (!response.ok || !JsonBool(response.body, "valid")) {
        OutputMessageUtf8("XWF session validation failed: " + (response.error.empty() ? CompactError(response.body) : response.error));
        return false;
    }
    return true;
}

static bool EnsureCollectionConsent() {
    if (!g_config.collection_consent_accepted) {
        OutputMessage(L"XWF collection consent was not accepted.");
        return false;
    }
    std::string session_id = Utf8FromWide(g_config.session_id);
    HttpResponse status = HttpRequest(g_config, L"GET", "/api/v1/collector/consent/status/" + session_id, std::string(), std::wstring());
    if (status.ok && JsonBool(status.body, "is_valid")) {
        return true;
    }
    HttpResponse tmpl = HttpRequest(g_config, L"GET", "/api/v1/collector/consent?language=en&category=collection", std::string(), std::wstring());
    if (!tmpl.ok) {
        OutputMessageUtf8("XWF consent template failed: " + tmpl.error);
        return false;
    }
    std::string template_id = JsonString(tmpl.body, "id");
    std::string version = JsonString(tmpl.body, "version");
    std::string language = JsonString(tmpl.body, "language");
    std::string agreed_items = JsonArrayRaw(tmpl.body, "required_checkboxes");
    if (template_id.empty() || version.empty() || agreed_items.empty()) {
        OutputMessage(L"XWF consent template is incomplete.");
        return false;
    }
    if (language.empty()) {
        language = "en";
    }
    std::string body = "{"
        "\"session_id\":\"" + JsonEscape(session_id) + "\","
        "\"case_id\":\"" + JsonEscape(Utf8FromWide(g_config.case_id)) + "\","
        "\"template_id\":\"" + JsonEscape(template_id) + "\","
        "\"consent_version\":\"" + JsonEscape(version) + "\","
        "\"consent_language\":\"" + JsonEscape(language) + "\","
        "\"agreed_items\":" + agreed_items + ","
        "\"collector_name\":\"" + JsonEscape(Utf8FromWide(g_config.operator_name)) + "\","
        "\"collector_organization\":\"\","
        "\"target_system_info\":{\"client\":\"xways_xtension\",\"transport\":\"native_xwf\",\"hardware_id\":\"" + JsonEscape(BuildHardwareId()) + "\",\"operator_role\":\"device_owner\",\"operator_legal_basis\":\"data_subject_consent\",\"international_transfer_ack\":true},"
        "\"signature_type\":\"checkbox\","
        "\"signature_data\":\"xways_operator_explicit_collection_consent\""
        "}";
    HttpResponse accepted = HttpRequest(g_config, L"POST", "/api/v1/collector/consent/accept", body, L"application/json");
    if (!accepted.ok) {
        OutputMessageUtf8("XWF consent accept failed: " + accepted.error);
        return false;
    }
    return true;
}

static bool MaybeHeartbeat() {
    ULONGLONG now = GetTickCount64();
    if (g_last_heartbeat_ms == 0 || now < g_last_heartbeat_ms) {
        g_last_heartbeat_ms = now;
        g_last_heartbeat_item = g_processed_count;
        return true;
    }
    if ((now - g_last_heartbeat_ms) >= kUploadHeartbeatMs || (g_processed_count - g_last_heartbeat_item) >= kUploadHeartbeatItemInterval) {
        g_last_heartbeat_ms = now;
        g_last_heartbeat_item = g_processed_count;
        return ValidateSession();
    }
    return true;
}

static std::string GetItemType(LONG item_id) {
#if UNJAENA_XWF_HAS_OFFICIAL_API
    if (XWF_GetItemType == NULL) {
        return std::string();
    }
    wchar_t type_buffer[256] = {0};
    LONG result = XWF_GetItemType(item_id, type_buffer, static_cast<DWORD>(sizeof(type_buffer) / sizeof(type_buffer[0])));
    if (result < 0 || type_buffer[0] == L'\0') {
        return std::string();
    }
    return Utf8FromWide(type_buffer);
#else
    UNREFERENCED_PARAMETER(item_id);
    return std::string();
#endif
}

static int64_t GetItemInfoInt64(LONG item_id, LONG info_type) {
#if UNJAENA_XWF_HAS_OFFICIAL_API
    if (XWF_GetItemInformation == NULL) {
        return 0;
    }
    BOOL success = FALSE;
    INT64 value = XWF_GetItemInformation(item_id, info_type, &success);
    return success ? static_cast<int64_t>(value) : 0;
#else
    UNREFERENCED_PARAMETER(item_id);
    UNREFERENCED_PARAMETER(info_type);
    return 0;
#endif
}

static ItemInfo BuildItemInfo(LONG item_id, HANDLE item) {
    ItemInfo info = {};
    info.item_id = item_id;
    info.item = item;
#if UNJAENA_XWF_HAS_OFFICIAL_API
    INT64 signed_size = XWF_GetItemSize == NULL ? -1 : XWF_GetItemSize(item_id);
    info.size = signed_size < 0 ? 0 : static_cast<uint64_t>(signed_size);
    const wchar_t* raw_name = XWF_GetItemName == NULL ? NULL : XWF_GetItemName(item_id);
    info.raw_path = raw_name == NULL ? L"" : raw_name;
    info.file_name = BaseName(info.raw_path);
    if (info.file_name.empty()) {
        info.file_name = L"xways_item.bin";
    }
    info.file_type = GetItemType(item_id);
#else
    UNREFERENCED_PARAMETER(item_id);
    UNREFERENCED_PARAMETER(item);
#endif
    info.normalized_path = NormalizePath(info.raw_path);
    info.normalized_name = LowerAscii(Utf8FromWide(info.file_name));
    info.extension = ExtensionFromName(info.normalized_name);
    return info;
}

static bool IsLikelyDirectory(const ItemInfo& item) {
    std::string type = LowerAscii(item.file_type);
    return type.find("directory") != std::string::npos || type.find("folder") != std::string::npos;
}

static std::string BuildMetadataJson(const ItemInfo& item) {
    std::ostringstream out;
    out << "{";
    out << "\"source_tool\":\"xways_xtension\",";
    out << "\"collection_method\":\"xways_xtension\",";
    out << "\"upload_method\":\"xways_raw_body\",";
    out << "\"original_path\":\"" << JsonEscape(Utf8FromWide(item.raw_path)) << "\",";
    out << "\"entry_path\":\"" << JsonEscape(Utf8FromWide(item.raw_path)) << "\",";
    out << "\"entry_name\":\"" << JsonEscape(Utf8FromWide(item.file_name)) << "\",";
    out << "\"entry_extension\":\"" << JsonEscape(item.extension) << "\",";
    out << "\"entry_logical_size\":\"" << item.size << "\",";
    out << "\"xways\":{";
    out << "\"item_id\":\"" << item.item_id << "\",";
    out << "\"scope\":\"" << (g_operation_type == XT_ACTION_DBC ? "selected_items" : (g_operation_type == XT_ACTION_RVS ? "volume_snapshot" : "tools_run")) << "\",";
    out << "\"file_type\":\"" << JsonEscape(item.file_type) << "\",";
    out << "\"parent_item_id\":" << (XWF_GetItemParent == NULL ? -1 : XWF_GetItemParent(item.item_id)) << ",";
    out << "\"classification\":" << GetItemInfoInt64(item.item_id, XWF_ITEM_INFO_CLASSIFICATION) << ",";
    out << "\"deletion_status\":" << GetItemInfoInt64(item.item_id, XWF_ITEM_INFO_DELETION);
    out << "}";
    out << "}";
    return out.str();
}

static bool UploadItem(const ItemInfo& item, const std::string& artifact_type) {
    std::string body = "{"
        "\"session_id\":\"" + JsonEscape(Utf8FromWide(g_config.session_id)) + "\","
        "\"collection_token\":\"" + JsonEscape(Utf8FromWide(g_config.collection_token)) + "\","
        "\"case_id\":\"" + JsonEscape(Utf8FromWide(g_config.case_id)) + "\","
        "\"file_name\":\"" + JsonEscape(Utf8FromWide(item.file_name)) + "\","
        "\"file_size\":" + std::to_string(item.size) + ","
        "\"file_hash\":null,"
        "\"artifact_type\":\"" + JsonEscape(artifact_type) + "\","
        "\"content_type\":\"application/octet-stream\","
        "\"profile_id\":" + JsonStringOrNull(Utf8FromWide(g_config.profile_id)) + ","
        "\"metadata\":" + BuildMetadataJson(item) +
        "}";
    HttpResponse init = HttpRequest(g_config, L"POST", "/api/v1/collector/xways/uploads/init", body, L"application/json");
    if (!init.ok) {
        OutputMessageUtf8("XWF upload init failed: " + init.error);
        return false;
    }
    std::string upload_url = JsonString(init.body, "upload_url");
    std::string complete_url = JsonString(init.body, "complete_url");
    std::string ticket = JsonString(init.body, "upload_ticket");
    if (upload_url.empty() || complete_url.empty() || ticket.empty()) {
        OutputMessage(L"XWF upload init response is missing upload_url, complete_url, or upload_ticket.");
        return false;
    }
    HttpResponse data = HttpPutItem(g_config, upload_url, item.item, item.size, ticket);
    if (!data.ok) {
        OutputMessageUtf8("XWF upload data failed: " + data.error);
        return false;
    }
    std::string complete_body = "{"
        "\"session_id\":\"" + JsonEscape(Utf8FromWide(g_config.session_id)) + "\","
        "\"collection_token\":\"" + JsonEscape(Utf8FromWide(g_config.collection_token)) + "\","
        "\"case_id\":\"" + JsonEscape(Utf8FromWide(g_config.case_id)) + "\""
        "}";
    HttpResponse complete = HttpRequest(g_config, L"POST", complete_url, complete_body, L"application/json", ticket);
    if (!complete.ok) {
        OutputMessageUtf8("XWF upload complete failed: " + complete.error);
        return false;
    }
    return true;
}

static bool InitializeCollector(HWND parent) {
    g_cancelled_by_user = false;
    OutputMessage(L"XWF collector initialization started.");
    ApplyCommandLineConfig(&g_config);
    if (g_config.session_token.empty() || !g_config.collection_consent_accepted) {
        if (!ShowConfigDialog(parent, &g_config)) {
            g_cancelled_by_user = true;
            OutputMessage(L"XWF collector configuration cancelled by user.");
            return false;
        }
    }
    OutputMessage(L"XWF collector authenticating with backend.");
    if (!Authenticate()) {
        return false;
    }
    OutputMessage(L"XWF collector authentication succeeded; loading collection profile.");
    if (!LoadCollectionProfile()) {
        return false;
    }
    OutputMessage(L"XWF collection profile loaded; verifying consent.");
    if (!EnsureCollectionConsent()) {
        return false;
    }
    OutputMessage(L"XWF consent verified; validating collection session.");
    if (!ValidateSession()) {
        return false;
    }
    OutputMessage(L"XWF collector initialization completed.");
    g_last_heartbeat_ms = GetTickCount64();
    g_last_heartbeat_item = 0;
    return true;
}

static bool CollectItem(LONG item_id, HANDLE item) {
#if UNJAENA_XWF_HAS_OFFICIAL_API
    if (!g_ready) {
        ++g_skipped_count;
        return false;
    }
    ++g_processed_count;
    if (!MaybeHeartbeat()) {
        ++g_failed_count;
        return false;
    }
    ItemInfo info = BuildItemInfo(item_id, item);
    if (info.size == 0) {
        ++g_skipped_count;
        ++g_skipped_zero_byte;
        return false;
    }
    if (IsLikelyDirectory(info)) {
        ++g_skipped_count;
        ++g_skipped_directory;
        return false;
    }
    if (info.size > kMaxDirectUploadBytes) {
        ++g_skipped_count;
        ++g_skipped_too_large;
        return false;
    }
    std::string artifact_type = MatchProfileArtifact(info);
    if (artifact_type.empty()) {
        ++g_skipped_count;
        ++g_skipped_no_profile_match;
        return false;
    }
    if (g_config.max_uploads > 0 && g_uploaded_count >= g_config.max_uploads) {
        ++g_skipped_count;
        return false;
    }
    if (UploadItem(info, artifact_type)) {
        ++g_uploaded_count;
        return true;
    }
    ++g_failed_count;
    return false;
#else
    UNREFERENCED_PARAMETER(item_id);
    UNREFERENCED_PARAMETER(item);
    ++g_failed_count;
    return false;
#endif
}

static void ResetRunState() {
    g_ready = false;
    g_cancelled_by_user = false;
    g_profile_targets.clear();
    g_processed_count = 0;
    g_uploaded_count = 0;
    g_skipped_count = 0;
    g_failed_count = 0;
    g_skipped_no_profile_match = 0;
    g_skipped_zero_byte = 0;
    g_skipped_directory = 0;
    g_skipped_too_large = 0;
    g_last_heartbeat_ms = 0;
    g_last_heartbeat_item = 0;
}

static void PrintSummary() {
    std::ostringstream out;
    out << "unJaena X-Ways Collector finished. uploaded=" << g_uploaded_count
        << ", processed=" << g_processed_count
        << ", skipped=" << g_skipped_count
        << ", failed=" << g_failed_count
        << ", no_profile_match=" << g_skipped_no_profile_match
        << ", zero_byte=" << g_skipped_zero_byte
        << ", directory=" << g_skipped_directory
        << ", too_large=" << g_skipped_too_large;
    OutputMessageUtf8(out.str());
}

static LONG ReportUnhandledException(const char* entry_name, const char* detail) {
    std::string message = "XWF collector unhandled exception in ";
    message += entry_name == NULL ? "unknown" : entry_name;
    if (detail != NULL && detail[0] != '\0') {
        message += ": ";
        message += detail;
    }
    OutputMessageUtf8(message);
    std::wstring wide = WideFromUtf8(message);
    if (g_main_window != NULL) {
        MessageBoxW(g_main_window, wide.c_str(), L"unJaena X-Ways Collector", MB_OK | MB_ICONERROR);
    }
    return 0;
}

}  // namespace unjaena_xwf

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    UNREFERENCED_PARAMETER(reserved);
    if (reason == DLL_PROCESS_ATTACH) {
        unjaena_xwf::g_module_instance = hModule;
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}

extern "C" LONG __stdcall XT_Init(DWORD nVersion, DWORD nFlags, HANDLE hMainWnd, void* lpReserved) {
    try {
        UNREFERENCED_PARAMETER(nVersion);
        UNREFERENCED_PARAMETER(lpReserved);
        unjaena_xwf::g_main_window = static_cast<HWND>(hMainWnd);
#if UNJAENA_XWF_HAS_OFFICIAL_API
        if ((nFlags & XT_INIT_QUICKCHECK) != 0) {
            return 1;
        }
        XT_RetrieveFunctionPointers();
        if (XWF_GetItemName == NULL || XWF_GetItemSize == NULL || XWF_Read == NULL) {
            unjaena_xwf::OutputMessage(L"unJaena X-Tension cannot start: required XWF item read functions are missing.");
            return 0;
        }
        unjaena_xwf::OutputMessage(L"unJaena X-Ways collector initialized.");
#else
        UNREFERENCED_PARAMETER(nFlags);
#endif
        return 1;
    } catch (const std::exception& ex) {
        return unjaena_xwf::ReportUnhandledException("XT_Init", ex.what());
    } catch (...) {
        return unjaena_xwf::ReportUnhandledException("XT_Init", "unknown exception");
    }
}

extern "C" LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved) {
    try {
        UNREFERENCED_PARAMETER(lpReserved);
        MessageBoxW(
            static_cast<HWND>(hParentWnd),
            L"unJaena X-Ways collector. Authenticates with unJaena, loads the collection profile, and uploads matched X-Ways items.",
            L"unJaena X-Tension",
            MB_OK | MB_ICONINFORMATION);
        return 1;
    } catch (const std::exception& ex) {
        return unjaena_xwf::ReportUnhandledException("XT_About", ex.what());
    } catch (...) {
        return unjaena_xwf::ReportUnhandledException("XT_About", "unknown exception");
    }
}

extern "C" LONG __stdcall XT_Done(void* lpReserved) {
    try {
        UNREFERENCED_PARAMETER(lpReserved);
        unjaena_xwf::OutputMessage(L"UnjaenaXwfCollector XT_Done called.");
    } catch (...) {
    }
    return 0;
}

extern "C" LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void* lpReserved) {
    try {
        UNREFERENCED_PARAMETER(hEvidence);
        UNREFERENCED_PARAMETER(lpReserved);
        unjaena_xwf::ResetRunState();
        unjaena_xwf::g_volume = hVolume;
        unjaena_xwf::g_operation_type = nOpType;

#if UNJAENA_XWF_HAS_OFFICIAL_API
        if (XWF_ShowProgress != NULL) {
            wchar_t caption[] = L"unJaena X-Ways collector";
            XWF_ShowProgress(caption, 0);
        }
#endif

        unjaena_xwf::g_ready = unjaena_xwf::InitializeCollector(unjaena_xwf::g_main_window);
        if (!unjaena_xwf::g_ready) {
            unjaena_xwf::OutputMessage(L"unJaena X-Ways collector was cancelled or failed during initialization.");
            if (!unjaena_xwf::g_cancelled_by_user && unjaena_xwf::g_main_window != NULL) {
                MessageBoxW(
                    unjaena_xwf::g_main_window,
                    L"unJaena X-Ways collector failed during initialization. Check %TEMP%\\UnjaenaXwfCollector.log for details.",
                    L"unJaena X-Ways Collector",
                    MB_OK | MB_ICONERROR);
            }
            return 0;
        }
        return 1;
    } catch (const std::exception& ex) {
        return unjaena_xwf::ReportUnhandledException("XT_Prepare", ex.what());
    } catch (...) {
        return unjaena_xwf::ReportUnhandledException("XT_Prepare", "unknown exception");
    }
}

extern "C" LONG __stdcall XT_Finalize(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void* lpReserved) {
    try {
        UNREFERENCED_PARAMETER(hVolume);
        UNREFERENCED_PARAMETER(hEvidence);
        UNREFERENCED_PARAMETER(nOpType);
        UNREFERENCED_PARAMETER(lpReserved);
        unjaena_xwf::PrintSummary();
#if UNJAENA_XWF_HAS_OFFICIAL_API
        if (XWF_HideProgress != NULL) {
            XWF_HideProgress();
        }
#endif
    } catch (const std::exception& ex) {
        return unjaena_xwf::ReportUnhandledException("XT_Finalize", ex.what());
    } catch (...) {
        return unjaena_xwf::ReportUnhandledException("XT_Finalize", "unknown exception");
    }
    return 0;
}

extern "C" LONG __stdcall XT_ProcessItem(LONG nItemID, void* lpReserved) {
    try {
        UNREFERENCED_PARAMETER(lpReserved);
#if UNJAENA_XWF_HAS_OFFICIAL_API
        if (unjaena_xwf::g_volume == NULL || XWF_OpenItem == NULL || XWF_Close == NULL) {
            return 0;
        }
        HANDLE item = XWF_OpenItem(unjaena_xwf::g_volume, nItemID, 0);
        if (item == NULL) {
            return 0;
        }
        unjaena_xwf::CollectItem(nItemID, item);
        XWF_Close(item);
#else
        UNREFERENCED_PARAMETER(nItemID);
#endif
    } catch (const std::exception& ex) {
        return unjaena_xwf::ReportUnhandledException("XT_ProcessItem", ex.what());
    } catch (...) {
        return unjaena_xwf::ReportUnhandledException("XT_ProcessItem", "unknown exception");
    }
    return 0;
}

extern "C" LONG __stdcall XT_ProcessItemEx(LONG nItemID, HANDLE hItem, void* lpReserved) {
    try {
        UNREFERENCED_PARAMETER(lpReserved);
        unjaena_xwf::CollectItem(nItemID, hItem);
#if UNJAENA_XWF_HAS_OFFICIAL_API
        if (XWF_SetProgressDescription != NULL) {
            std::wstring message = L"Processed item " + std::to_wstring(nItemID);
            XWF_SetProgressDescription(const_cast<wchar_t*>(message.c_str()));
        }
#endif
    } catch (const std::exception& ex) {
        return unjaena_xwf::ReportUnhandledException("XT_ProcessItemEx", ex.what());
    } catch (...) {
        return unjaena_xwf::ReportUnhandledException("XT_ProcessItemEx", "unknown exception");
    }
    return 0;
}
