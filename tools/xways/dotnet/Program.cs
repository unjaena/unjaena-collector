using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;
using UnjaenaEncaseBridge;

namespace UnjaenaXwfPackageUploader
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            Options options;
            string error = Options.TryParse(args, out options);
            if (!string.IsNullOrEmpty(error))
            {
                Console.Error.WriteLine(error);
                PrintUsage();
                return 2;
            }

            PackageManifest manifest;
            error = PackageManifest.TryLoad(options.ManifestPath, out manifest);
            if (!string.IsNullOrEmpty(error))
            {
                Console.Error.WriteLine(error);
                return 2;
            }

            var client = new CollectorClient();
            client.ConfigureClientIdentity(
                "/api/v1/collector/xways/authenticate",
                "/api/v1/collector/xways/uploads/init",
                "X-XWays-Upload-Ticket",
                "xways_package_uploader",
                "external_dotnet",
                "xways_xtension",
                "X-Ways operator",
                "unJaena-XWays-PackageUploader/1.0");
            string hardwareId = "xways-" + Environment.MachineName;
            string authResponse = client.Authenticate(
                options.Host,
                options.Port,
                options.UseSsl,
                options.SessionToken,
                hardwareId);
            if (!client.WasLastSucceeded())
            {
                Console.Error.WriteLine("Authentication failed: " + client.GetLastError());
                return 1;
            }

            string sessionId = JsonValue(authResponse, "session_id");
            string collectionToken = JsonValue(authResponse, "collection_token");
            string caseId = string.IsNullOrEmpty(options.CaseId) ? manifest.CaseId : options.CaseId;
            if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(collectionToken) || string.IsNullOrEmpty(caseId))
            {
                Console.Error.WriteLine("Authentication response or manifest did not include required session/case fields.");
                return 1;
            }

            string profileResponse = client.LoadCollectionProfile(
                options.Host,
                options.Port,
                options.UseSsl,
                sessionId,
                collectionToken);
            if (!client.WasLastSucceeded())
            {
                Console.Error.WriteLine("Collection profile load failed: " + client.GetLastError());
                return 1;
            }

            string consentResponse = client.EnsureCollectionConsent(
                options.Host,
                options.Port,
                options.UseSsl,
                sessionId,
                caseId,
                options.CollectorName,
                options.CollectorOrganization,
                options.Language,
                hardwareId);
            if (!client.WasLastSucceeded())
            {
                Console.Error.WriteLine("Collection consent failed: " + client.GetLastError());
                return 1;
            }

            int uploaded = 0;
            int skipped = 0;
            string packageRoot = Path.GetDirectoryName(Path.GetFullPath(options.ManifestPath));
            foreach (Artifact artifact in manifest.Artifacts)
            {
                string artifactPath = Path.Combine(packageRoot, artifact.RelativePath.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(artifactPath))
                {
                    Console.Error.WriteLine("Skipping missing package file: " + artifact.RelativePath);
                    skipped++;
                    continue;
                }

                string metadataJson = artifact.ToMetadataJson(manifest);
                string uploadResponse = client.UploadFile(
                    options.Host,
                    options.Port,
                    options.UseSsl,
                    caseId,
                    sessionId,
                    collectionToken,
                    artifact.ArtifactType,
                    artifact.FileName,
                    artifactPath,
                    artifact.Sha256,
                    metadataJson);
                if (!client.WasLastSucceeded())
                {
                    Console.Error.WriteLine("Upload failed for " + artifact.RelativePath + ": " + client.GetLastError());
                    return 1;
                }

                uploaded++;
                if (options.Verbose)
                {
                    Console.WriteLine("Uploaded " + artifact.RelativePath + ": " + uploadResponse);
                }
            }

            Console.WriteLine("X-Ways package upload complete. uploaded=" + uploaded + " skipped=" + skipped);
            return 0;
        }

        private static string JsonValue(string json, string key)
        {
            try
            {
                var serializer = new JavaScriptSerializer();
                var obj = serializer.DeserializeObject(json) as Dictionary<string, object>;
                if (obj == null || !obj.ContainsKey(key) || obj[key] == null)
                {
                    return string.Empty;
                }
                return Convert.ToString(obj[key]);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine(
                "Usage: UnjaenaXwfPackageUploader --manifest <manifest.json> --host <host> --token <session-id:secret> [--port 443] [--http] [--case-id <id>]");
        }
    }

    internal sealed class Options
    {
        public string ManifestPath;
        public string Host;
        public int Port = 443;
        public bool UseSsl = true;
        public string SessionToken;
        public string CaseId;
        public string CollectorName = "X-Ways operator";
        public string CollectorOrganization = "";
        public string Language = "en";
        public bool Verbose;

        public static string TryParse(string[] args, out Options options)
        {
            options = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                string value = i + 1 < args.Length ? args[i + 1] : null;
                switch (arg)
                {
                    case "--manifest":
                        options.ManifestPath = RequireValue(arg, value);
                        i++;
                        break;
                    case "--host":
                        options.Host = RequireValue(arg, value);
                        i++;
                        break;
                    case "--port":
                        string portValue = RequireValue(arg, value);
                        int port;
                        if (!int.TryParse(portValue, out port) || port <= 0)
                        {
                            return "--port must be a positive integer.";
                        }
                        options.Port = port;
                        i++;
                        break;
                    case "--http":
                        options.UseSsl = false;
                        if (options.Port == 443)
                        {
                            options.Port = 80;
                        }
                        break;
                    case "--token":
                        options.SessionToken = RequireValue(arg, value);
                        i++;
                        break;
                    case "--case-id":
                        options.CaseId = RequireValue(arg, value);
                        i++;
                        break;
                    case "--collector-name":
                        options.CollectorName = RequireValue(arg, value);
                        i++;
                        break;
                    case "--collector-organization":
                        options.CollectorOrganization = RequireValue(arg, value);
                        i++;
                        break;
                    case "--language":
                        options.Language = RequireValue(arg, value);
                        i++;
                        break;
                    case "--verbose":
                        options.Verbose = true;
                        break;
                    default:
                        return "Unknown argument: " + arg;
                }
            }

            if (string.IsNullOrEmpty(options.ManifestPath) || !File.Exists(options.ManifestPath))
            {
                return "--manifest is required and must exist.";
            }
            if (string.IsNullOrEmpty(options.Host))
            {
                return "--host is required.";
            }
            if (string.IsNullOrEmpty(options.SessionToken))
            {
                return "--token is required.";
            }
            return null;
        }

        private static string RequireValue(string arg, string value)
        {
            if (string.IsNullOrEmpty(value) || value.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException(arg + " requires a value.");
            }
            return value;
        }
    }

    internal sealed class PackageManifest
    {
        public string Format;
        public int FormatVersion;
        public string SourceTool;
        public string CaseId;
        public string ProfileId;
        public List<Artifact> Artifacts = new List<Artifact>();

        public static string TryLoad(string path, out PackageManifest manifest)
        {
            manifest = null;
            try
            {
                var serializer = new JavaScriptSerializer();
                var root = serializer.DeserializeObject(File.ReadAllText(path)) as Dictionary<string, object>;
                if (root == null)
                {
                    return "Manifest root must be a JSON object.";
                }

                var loaded = new PackageManifest();
                loaded.Format = AsString(root, "format");
                loaded.FormatVersion = AsInt(root, "format_version");
                loaded.SourceTool = AsString(root, "source_tool");
                if (loaded.Format != "unjaena.xways.package" || loaded.FormatVersion != 1 || loaded.SourceTool != "xways_xtension")
                {
                    return "Manifest format is not a supported unJaena X-Ways package.";
                }

                var caseObj = AsDict(root, "case");
                var profileObj = AsDict(root, "collection_profile");
                loaded.CaseId = AsString(caseObj, "case_id");
                loaded.ProfileId = AsString(profileObj, "profile_id");

                object artifactsRaw;
                if (!root.TryGetValue("artifacts", out artifactsRaw))
                {
                    return "Manifest missing artifacts.";
                }
                object[] artifactArray = artifactsRaw as object[];
                if (artifactArray == null)
                {
                    return "Manifest artifacts must be an array.";
                }

                foreach (object itemRaw in artifactArray)
                {
                    var item = itemRaw as Dictionary<string, object>;
                    if (item == null)
                    {
                        return "Artifact entry must be an object.";
                    }
                    var artifact = new Artifact();
                    artifact.ArtifactId = AsString(item, "artifact_id");
                    artifact.ArtifactType = AsString(item, "artifact_type");
                    artifact.FileName = AsString(item, "file_name");
                    artifact.RelativePath = AsString(item, "relative_path");
                    artifact.OriginalPath = AsString(item, "original_path");
                    artifact.Size = AsLong(item, "size");
                    artifact.Sha256 = AsString(item, "sha256");
                    artifact.Raw = item;
                    if (string.IsNullOrEmpty(artifact.ArtifactId)
                        || string.IsNullOrEmpty(artifact.ArtifactType)
                        || string.IsNullOrEmpty(artifact.FileName)
                        || string.IsNullOrEmpty(artifact.RelativePath))
                    {
                        return "Artifact entry is missing required fields.";
                    }
                    loaded.Artifacts.Add(artifact);
                }

                manifest = loaded;
                return null;
            }
            catch (Exception ex)
            {
                return "Failed to load manifest: " + ex.Message;
            }
        }

        private static Dictionary<string, object> AsDict(Dictionary<string, object> obj, string key)
        {
            object value;
            if (obj == null || !obj.TryGetValue(key, out value))
            {
                return new Dictionary<string, object>();
            }
            return value as Dictionary<string, object> ?? new Dictionary<string, object>();
        }

        private static string AsString(Dictionary<string, object> obj, string key)
        {
            object value;
            if (obj == null || !obj.TryGetValue(key, out value) || value == null)
            {
                return string.Empty;
            }
            return Convert.ToString(value);
        }

        private static int AsInt(Dictionary<string, object> obj, string key)
        {
            object value;
            if (obj == null || !obj.TryGetValue(key, out value) || value == null)
            {
                return 0;
            }
            return Convert.ToInt32(value);
        }

        private static long AsLong(Dictionary<string, object> obj, string key)
        {
            object value;
            if (obj == null || !obj.TryGetValue(key, out value) || value == null)
            {
                return 0;
            }
            return Convert.ToInt64(value);
        }
    }

    internal sealed class Artifact
    {
        public string ArtifactId;
        public string ArtifactType;
        public string FileName;
        public string RelativePath;
        public string OriginalPath;
        public long Size;
        public string Sha256;
        public Dictionary<string, object> Raw;

        public string ToMetadataJson(PackageManifest manifest)
        {
            var serializer = new JavaScriptSerializer();
            var metadata = new Dictionary<string, object>();
            metadata["source_tool"] = "xways_xtension";
            metadata["collection_method"] = "xways_xtension_package";
            metadata["upload_method"] = "xways_package_bridge";
            metadata["artifact_id"] = ArtifactId;
            metadata["original_path"] = OriginalPath;
            metadata["entry_path"] = OriginalPath;
            metadata["relative_path"] = RelativePath;
            metadata["xways"] = Raw != null && Raw.ContainsKey("xways") ? Raw["xways"] : new Dictionary<string, object>();
            metadata["collection_profile"] = new Dictionary<string, object>
            {
                {"profile_id", manifest.ProfileId}
            };
            return serializer.Serialize(metadata);
        }
    }
}
