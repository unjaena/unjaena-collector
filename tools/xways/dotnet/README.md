# unJaena X-Ways Package Uploader

This helper uploads a package produced by the X-Ways X-Tension. It runs outside
the X-Ways process and links the existing EnCase bridge `CollectorClient` so
authentication, collection profile loading, consent, upload init, upload data,
and completion use the same reviewed transport code path.

Build:

```powershell
msbuild .\UnjaenaXwfPackageUploader.csproj /p:Configuration=Release
```

Usage:

```powershell
.\bin\Release\net472\UnjaenaXwfPackageUploader.exe `
  --manifest C:\Cases\unjaena-xways-package\manifest.json `
  --host app.unjaena.com `
  --token "<session-id>:<secret>"
```

The helper configures the shared `CollectorClient` to use the X-Ways collector
endpoints: `/api/v1/collector/xways/authenticate` and
`/api/v1/collector/xways/uploads/init`. Completed uploads are tagged as
`xways_xtension` in metadata and chain-of-custody records when the backend with
the X-Ways route alias is deployed.
