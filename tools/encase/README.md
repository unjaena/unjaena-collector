# unJaena EnCase Integration

This directory contains the source package for using unJaena Collector from OpenText EnCase.

## Files

- `UnjaenaCollector.EnScript`: EnScript entry point for selected-entry upload.
- `dotnet/CollectorClient.cs`: .NET bridge for authenticated API calls, collection profile loading, consent submission, and upload transport.
- `dotnet/UnjaenaEncaseBridge.csproj`: MSBuild project that builds `UnjaenaEncaseBridge.dll`.

Generated binaries, documentation archives, local simulations, test caches, and base64 build artifacts are intentionally not included in the public repository.

## Security model

The EnCase integration follows the same public-client boundary as the desktop collector:

- The operator authenticates with a case session token.
- The service returns scoped session credentials and a server collection profile.
- Local matching uses only the server-supplied profile.
- Upload init requests include `profile_id` so the backend can enforce authorized targets.
- Upload data is sent through server-issued upload tickets.
- Consent must be explicitly confirmed before upload.
- Server responses are not printed verbatim to EnCase logs.

The public EnScript does not include proprietary parsers, product-specific target catalogs, scoring rules, or analysis logic.

## Build

Build the bridge on Windows with MSBuild for .NET Framework 4.7.2 or later:

```powershell
msbuild .\dotnet\UnjaenaEncaseBridge.csproj /p:Configuration=Release
```

The expected output is `UnjaenaEncaseBridge.dll`. Embed or place that DLL according to your EnCase deployment process so the EnScript `assembly embed "UnjaenaEncaseBridge.dll"` reference can resolve.

## Operation

1. Open the case in EnCase and select the entries to upload.
2. Run `UnjaenaCollector.EnScript`.
3. Enter the service host, keep TLS enabled, and paste the full `session-id:secret` session token from the unJaena case page.
4. Confirm collection authority and consent.
5. Review the console summary for uploaded, skipped, and failed entries.

Do not paste production tokens, customer evidence, credentials, or private logs into public issues.
