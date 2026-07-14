# unJaena X-Ways X-Tension Collector

This directory contains the X-Ways Forensics X-Tension collector for unJaena.
Its primary runtime behavior must match the public collector and EnScript
collector path: the DLL runs inside X-Ways, asks the analyst for the service
address and case session token, authenticates with the backend, loads the active
collection profile, verifies collection consent, matches X-Ways items against
server-provided artifact targets, and uploads matched item bytes through the
backend raw-body upload API.

The current primary flow is direct collection and direct upload. The historical
package manifest files and .NET uploader remain only as compatibility utilities
for isolated field testing; they are not the production XWF collection path.

## Files

- `src/UnjaenaXwfCollector.template.cpp`: native X-Tension source implementing
  `XT_Init`, `XT_Prepare`, `XT_ProcessItem`, `XT_ProcessItemEx`, and
  `XT_Finalize`.
- `native/UnjaenaXwfCollector.vcxproj`: Visual Studio x64 DLL project for the
  X-Tension build.
- `native/xwf_api.local.props.example`: local-only MSBuild property sheet for
  the official XWF API header location.
- `native/UnjaenaXwfCollector.def`: undecorated X-Tension exports for X-Ways.
- `package_manifest.schema.json`, `examples/`, `tools/validate_package.py`, and
  `dotnet/`: legacy package validation/upload helpers retained for compatibility
  testing only.

Generated DLLs, official XWF API archives, local property sheets, customer
evidence, case tokens, logs, and upload packages must not be committed.

## Production runtime flow

1. Open the evidence case in X-Ways Forensics.
2. Load `UnjaenaXwfCollector.dll` as an X-Tension.
3. Run the X-Tension from the directory browser context menu or
   `Tools > Run X-Tensions`.
4. Enter the unJaena service host, port, SSL option, and case session token in
   the dialog. The dialog also requires explicit collection consent.
5. The X-Tension authenticates with `/api/v1/collector/xways/authenticate`.
6. It loads `/api/v1/collector/collection/profile` with `X-Session-ID` and
   `X-Collection-Token`.
7. It validates collection consent and refreshes session heartbeat while X-Ways
   enumerates items.
8. For every item that X-Ways passes to `XT_ProcessItem` or `XT_ProcessItemEx`,
   the X-Tension compares the item path/name/extension/size to the collection
   profile targets.
9. Matched items are uploaded as raw bytes through
   `/api/v1/collector/xways/uploads/init`, the returned PUT `upload_url`, and
   the returned `complete_url` using `X-XWays-Upload-Ticket`.
10. The backend continues with the same parser, embedding, manual analysis,
    timeline, graph, and AI analysis workflow as other collectors.

The X-Tension also accepts non-interactive parameters in this form:

```text
XTParam:UNJAENA:host=app.unjaena.com;port=443;ssl=true;token=<session-id:secret>;consent=true;max_uploads=100
```

`max_uploads` is accepted only as a non-interactive smoke-test parameter. It is
not shown in the production dialog and should be omitted in normal runs.

## Security model

The X-Ways integration follows the same public-client boundary as the desktop
collector and EnScript collector:

- The X-Tension does not store service credentials.
- The operator must provide a valid case session token in `session-id:secret`
  form.
- The backend validates case/session authorization, collection consent, profile
  gates, case readiness, payment/credit gates, and upload limits.
- Upload URLs returned by the backend are constrained to the configured service
  host before the DLL sends bytes.
- The DLL is read-only toward evidence. It does not modify evidence objects,
  delete search hits, write comments/report tables, or launch arbitrary tools.
- Files larger than the direct raw-body safety limit are skipped and reported in
  the final summary instead of being partially uploaded.

## Build notes

The X-Tension source intentionally does not vendor the official XWF API headers.
Download the official C/C++ XWF API package from SourceForge and keep it in a
local build folder outside Git.

Build on Windows with Visual Studio 2022 Build Tools:

```powershell
cd .\native
Copy-Item .\xwf_api.local.props.example .\xwf_api.local.props
notepad .\xwf_api.local.props
msbuild .\UnjaenaXwfCollector.vcxproj /p:Configuration=Release /p:Platform=x64
```

Expected output:

```text
..\bin\Release\x64\UnjaenaXwfCollector.dll
```

## Runtime smoke test checklist

- Load the DLL in X-Ways with a non-customer test image.
- Use a freshly generated unJaena collection session token.
- Confirm the dialog accepts host, port, SSL, token, and consent.
- Confirm authentication, profile loading, consent verification, and heartbeat
  messages appear in X-Ways output. If X-Ways does not show a message, inspect
  `%TEMP%\UnjaenaXwfCollector.log`; the DLL writes initialization, auth,
  profile, consent, heartbeat, upload, and exception diagnostics there.
- Run the X-Tension twice in the same X-Ways process to confirm the config
  dialog can be recreated and the DLL can be reloaded without crashing X-Ways.
- Run with a small `max_uploads` value first and verify uploaded artifacts appear
  in the target case.
- Confirm the uploaded artifact types match the collection profile and are later
  visible in parsing/manual analysis/timeline/relationship/AI workflows.

Do not paste production tokens, customer evidence, credentials, or private logs
into public issues.
