# Native X-Tension Build

This project builds `UnjaenaXwfCollector.dll` as an x64 X-Ways X-Tension.
The DLL is the production collector for X-Ways: it authenticates with unJaena,
loads the active collection profile, matches X-Ways items, and uploads matched
item bytes directly to the X-Ways raw-body collector endpoints.

## Prerequisites

- Windows 10/11 or Windows Server build host
- Visual Studio 2022 Build Tools with MSVC v143
- X-Ways Forensics installed for runtime validation
- Official XWF API C/C++ package downloaded from SourceForge

Do not commit the official XWF API package, local SDK paths, generated DLLs,
customer evidence, tokens, or private logs.

## Configure XWF API Source Path

Copy the local property sheet example:

```powershell
Copy-Item .\xwf_api.local.props.example .\xwf_api.local.props
```

Edit `xwf_api.local.props` and point `XwfApiSourceDir` at the official XWF API
`src` directory. The project uses that directory for `X-Tension.h`; the
collector resolves the XWF function pointers it uses at runtime.
`UnjaenaXwfCollector.def` exports the required `XT_*` entry points with
undecorated names so X-Ways can locate them.

## Build

From a Visual Studio Developer PowerShell:

```powershell
msbuild .\UnjaenaXwfCollector.vcxproj /p:Configuration=Release /p:Platform=x64
```

Expected output:

```text
..\bin\Release\x64\UnjaenaXwfCollector.dll
```

## Runtime Smoke Test

1. Start X-Ways Forensics with a non-customer test case.
2. Load `UnjaenaXwfCollector.dll` as an X-Tension.
3. Run it from selected directory-browser items or `Tools > Run X-Tensions`.
4. In the dialog, enter host, port, SSL mode, `session-id:secret`, and accept
   collection consent.
5. For automated smoke tests, pass the same values with:

```text
XTParam:UNJAENA:host=app.unjaena.com;port=443;ssl=true;token=<session-id:secret>;consent=true;max_uploads=10
```

6. Confirm X-Ways output shows authentication, profile loading, consent check,
   heartbeat validation, upload counts, and skipped counts. If no message is
   visible, inspect `%TEMP%\UnjaenaXwfCollector.log`.
7. Run the DLL twice in the same X-Ways process to verify the configuration
   window class is unregistered after use and X-Ways remains open.
8. Confirm uploaded artifacts are visible in the unJaena case and continue into
   parsing, embedding, manual analysis, timeline, relationship analysis, and AI
   analysis.

The DLL implements `XT_Init`, `XT_Prepare`, `XT_ProcessItem`,
`XT_ProcessItemEx`, and `XT_Finalize`. It uses XWF item APIs for names, sizes,
metadata, and byte reads, and WinHTTP for authenticated raw-body upload.
