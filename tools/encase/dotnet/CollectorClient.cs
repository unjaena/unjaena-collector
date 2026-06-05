using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace UnjaenaEncaseBridge
{
    public class CollectorClient
    {
        private sealed class CollectionProfileTarget
        {
            public string ArtifactType;
            public string Kind;
            public string[] Patterns;
            public long MaxBytes;
        }

        private static readonly object ProfileLock = new object();
        private static string collectionProfileId = string.Empty;
        private static CollectionProfileTarget[] collectionProfileTargets = new CollectionProfileTarget[0];

        public int LastStatusCode { get; private set; }
        public string LastError { get; private set; }
        public bool LastSucceeded { get; private set; }

        public bool WasLastSucceeded()
        {
            return LastSucceeded;
        }

        public int GetLastStatusCode()
        {
            return LastStatusCode;
        }

        public string GetLastError()
        {
            return LastError ?? string.Empty;
        }

        public string Authenticate(
            string host,
            uint port,
            bool useSsl,
            string sessionToken,
            string hardwareId)
        {
            return Authenticate(host, PortToInt(port), useSsl, sessionToken, hardwareId);
        }

        public string Authenticate(
            string host,
            int port,
            bool useSsl,
            string sessionToken,
            string hardwareId)
        {
            ClearState();

            if (IsBlank(host) || IsBlank(sessionToken) || IsBlank(hardwareId))
            {
                return ErrorJson("invalid_argument", "host, sessionToken, and hardwareId are required.");
            }

            string url = BuildUrl(host, port, useSsl, "/api/v1/collector/encase/authenticate");
            string body =
                "{"
                + "\"session_token\":\"" + JsonEscape(sessionToken) + "\","
                + "\"hardware_id\":\"" + JsonEscape(hardwareId) + "\","
                + "\"client_info\":{\"client\":\"encase_dotnet\",\"mode\":\"embedded_dotnet\",\"version\":\"1.0.0\"}"
                + "}";

            return PostJson(url, body);
        }

        public string LoadCollectionProfile(
            string host,
            uint port,
            bool useSsl,
            string sessionId,
            string collectionToken)
        {
            return LoadCollectionProfile(host, PortToInt(port), useSsl, sessionId, collectionToken);
        }

        public string LoadCollectionProfile(
            string host,
            int port,
            bool useSsl,
            string sessionId,
            string collectionToken)
        {
            ClearState();

            if (IsBlank(host) || IsBlank(sessionId) || IsBlank(collectionToken))
            {
                return ErrorJson("invalid_argument", "host, sessionId, and collectionToken are required.");
            }

            string url = BuildUrl(host, port, useSsl, "/api/v1/collector/collection/profile");
            string response = PostJson(url, "{}", null, sessionId, collectionToken);
            if (!LastSucceeded)
            {
                return response;
            }

            string profileId = JsonString(response, "profile_id");
            CollectionProfileTarget[] targets = ParseCollectionProfileTargets(response);
            if (IsBlank(profileId))
            {
                return ErrorJson("invalid_collection_profile", "Collection profile response missing profile_id.");
            }
            if (targets.Length == 0)
            {
                return ErrorJson("invalid_collection_profile", "Collection profile response has no authorized targets.");
            }

            lock (ProfileLock)
            {
                collectionProfileId = profileId;
                collectionProfileTargets = targets;
            }

            LastSucceeded = true;
            LastStatusCode = 200;
            LastError = null;
            return response;
        }

        public string GetCollectionProfileId()
        {
            lock (ProfileLock)
            {
                return collectionProfileId ?? string.Empty;
            }
        }

        public int GetCollectionProfileTargetCount()
        {
            lock (ProfileLock)
            {
                return collectionProfileTargets == null ? 0 : collectionProfileTargets.Length;
            }
        }

        public string ValidateSession(
            string host,
            uint port,
            bool useSsl,
            string sessionId,
            string collectionToken)
        {
            return ValidateSession(host, PortToInt(port), useSsl, sessionId, collectionToken);
        }

        public string ValidateSession(
            string host,
            int port,
            bool useSsl,
            string sessionId,
            string collectionToken)
        {
            ClearState();

            if (IsBlank(host) || IsBlank(sessionId) || IsBlank(collectionToken))
            {
                return ErrorJson("invalid_argument", "host, sessionId, and collectionToken are required.");
            }

            string profileId = GetCollectionProfileId();
            string url = BuildUrl(host, port, useSsl, "/api/v1/collector/validate-session");
            string body =
                "{"
                + "\"session_id\":\"" + JsonEscape(sessionId) + "\","
                + "\"collection_token\":\"" + JsonEscape(collectionToken) + "\","
                + "\"profile_id\":" + JsonStringOrNull(profileId)
                + "}";

            string response = PostJson(url, body);
            if (LastSucceeded && !JsonBool(response, "valid"))
            {
                LastSucceeded = false;
                LastStatusCode = 409;
                LastError = ResponseErrorSummary(response);
            }
            return response;
        }

        public string MatchProfileArtifact(
            string path,
            string name,
            string extension,
            long fileSize)
        {
            ClearState();

            string normalizedPath = NormalizeMatchValue(path);
            string normalizedName = NormalizeMatchValue(IsBlank(name) ? PathLeaf(normalizedPath) : name);
            CollectionProfileTarget[] targets;
            lock (ProfileLock)
            {
                targets = collectionProfileTargets ?? new CollectionProfileTarget[0];
            }

            if (targets.Length == 0)
            {
                LastSucceeded = false;
                LastStatusCode = 0;
                LastError = "collection_profile_not_loaded";
                return string.Empty;
            }

            for (int i = 0; i < targets.Length; i++)
            {
                CollectionProfileTarget target = targets[i];
                if (target == null || IsBlank(target.ArtifactType) || target.Patterns == null)
                {
                    continue;
                }
                if (target.MaxBytes > 0 && fileSize > 0 && fileSize > target.MaxBytes)
                {
                    continue;
                }
                for (int j = 0; j < target.Patterns.Length; j++)
                {
                    string[] patternVariants = ExpandCollectionPatternVariants(target.Patterns[j]);
                    for (int k = 0; k < patternVariants.Length; k++)
                    {
                        string pattern = patternVariants[k];
                        if (IsBlank(pattern))
                        {
                            continue;
                        }

                        bool pathPattern = pattern.IndexOf('/') >= 0 || pattern.IndexOf(':') >= 0;
                        string candidate = pathPattern ? normalizedPath : normalizedName;
                        if (WildcardMatch(candidate, pattern))
                        {
                            LastSucceeded = true;
                            LastStatusCode = 200;
                            LastError = null;
                            return target.ArtifactType;
                        }
                        if (pathPattern && !pattern.StartsWith("*", StringComparison.Ordinal) && WildcardMatch(normalizedPath, "*" + pattern))
                        {
                            LastSucceeded = true;
                            LastStatusCode = 200;
                            LastError = null;
                            return target.ArtifactType;
                        }
                    }
                }
            }

            LastSucceeded = true;
            LastStatusCode = 200;
            LastError = null;
            return string.Empty;
        }

        public string MatchProfileArtifact(
            string path,
            string name,
            string extension,
            ulong fileSize)
        {
            return MatchProfileArtifact(path, name, extension, ULongToLong(fileSize));
        }

        public string EnsureCollectionConsent(
            string host,
            uint port,
            bool useSsl,
            string sessionId,
            string caseId,
            string collectorName,
            string collectorOrganization,
            string language,
            string hardwareId)
        {
            return EnsureCollectionConsent(
                host,
                PortToInt(port),
                useSsl,
                sessionId,
                caseId,
                collectorName,
                collectorOrganization,
                language,
                hardwareId);
        }

        public string EnsureCollectionConsent(
            string host,
            int port,
            bool useSsl,
            string sessionId,
            string caseId,
            string collectorName,
            string collectorOrganization,
            string language,
            string hardwareId)
        {
            ClearState();

            if (IsBlank(host) || IsBlank(sessionId) || IsBlank(caseId))
            {
                return ErrorJson("invalid_argument", "host, sessionId, and caseId are required.");
            }

            string effectiveLanguage = IsBlank(language) ? "en" : language;
            string statusUrl = BuildUrl(
                host,
                port,
                useSsl,
                "/api/v1/collector/consent/status/" + Uri.EscapeDataString(sessionId));
            string statusResponse = GetJson(statusUrl);
            if (LastSucceeded && JsonBool(statusResponse, "is_valid"))
            {
                return statusResponse;
            }

            string templateUrl = BuildUrl(
                host,
                port,
                useSsl,
                "/api/v1/collector/consent?language="
                    + Uri.EscapeDataString(effectiveLanguage)
                    + "&category=collection");
            string templateResponse = GetJson(templateUrl);
            if (!LastSucceeded)
            {
                return templateResponse;
            }

            string templateId = JsonString(templateResponse, "id");
            string version = JsonString(templateResponse, "version");
            string templateLanguage = JsonString(templateResponse, "language");
            string agreedItems = JsonStringArray(templateResponse, "required_checkboxes");
            if (IsBlank(templateId) || IsBlank(version) || IsBlank(agreedItems))
            {
                return ErrorJson("invalid_consent_template", "Collection consent template is incomplete.");
            }
            if (IsBlank(templateLanguage))
            {
                templateLanguage = effectiveLanguage;
            }

            string acceptUrl = BuildUrl(host, port, useSsl, "/api/v1/collector/consent/accept");
            string body =
                "{"
                + "\"session_id\":\"" + JsonEscape(sessionId) + "\","
                + "\"case_id\":\"" + JsonEscape(caseId) + "\","
                + "\"template_id\":\"" + JsonEscape(templateId) + "\","
                + "\"consent_version\":\"" + JsonEscape(version) + "\","
                + "\"consent_language\":\"" + JsonEscape(templateLanguage) + "\","
                + "\"agreed_items\":" + agreedItems + ","
                + "\"collector_name\":\"" + JsonEscape(IsBlank(collectorName) ? "EnCase operator" : collectorName) + "\","
                + "\"collector_organization\":\"" + JsonEscape(collectorOrganization ?? string.Empty) + "\","
                + "\"target_system_info\":{"
                + "\"client\":\"encase_enscript\","
                + "\"transport\":\"embedded_dotnet\","
                + "\"hardware_id\":\"" + JsonEscape(hardwareId ?? string.Empty) + "\","
                + "\"operator_role\":\"device_owner\","
                + "\"operator_legal_basis\":\"data_subject_consent\","
                + "\"international_transfer_ack\":true"
                + "},"
                + "\"signature_type\":\"checkbox\","
                + "\"signature_data\":\"encase_operator_explicit_collection_consent\""
                + "}";

            return PostJson(acceptUrl, body);
        }

        public string UploadFile(
            string host,
            uint port,
            bool useSsl,
            string caseId,
            string sessionId,
            string collectionToken,
            string artifactType,
            string fileName,
            string filePath,
            string sha256,
            string metadataJson)
        {
            return UploadFile(
                host,
                PortToInt(port),
                useSsl,
                caseId,
                sessionId,
                collectionToken,
                artifactType,
                fileName,
                filePath,
                sha256,
                metadataJson);
        }

        public string UploadFile(
            string host,
            int port,
            bool useSsl,
            string caseId,
            string sessionId,
            string collectionToken,
            string artifactType,
            string fileName,
            string filePath,
            string sha256,
            string metadataJson)
        {
            ClearState();

            if (IsBlank(filePath) || !File.Exists(filePath))
            {
                return ErrorJson("file_not_found", "filePath does not exist.");
            }

            using (FileStream input = File.OpenRead(filePath))
            {
                string effectiveName = IsBlank(fileName) ? Path.GetFileName(filePath) : fileName;
                return UploadStream(
                    host,
                    port,
                    useSsl,
                    caseId,
                    sessionId,
                    collectionToken,
                    artifactType,
                    effectiveName,
                    input.Length,
                    sha256,
                    metadataJson,
                    input);
            }
        }

        public string UploadStream(
            string host,
            uint port,
            bool useSsl,
            string caseId,
            string sessionId,
            string collectionToken,
            string artifactType,
            string fileName,
            long fileSize,
            string sha256,
            string metadataJson,
            Stream inputStream)
        {
            return UploadStream(
                host,
                PortToInt(port),
                useSsl,
                caseId,
                sessionId,
                collectionToken,
                artifactType,
                fileName,
                fileSize,
                sha256,
                metadataJson,
                inputStream);
        }

        public string UploadStream(
            string host,
            uint port,
            bool useSsl,
            string caseId,
            string sessionId,
            string collectionToken,
            string artifactType,
            string fileName,
            ulong fileSize,
            string sha256,
            string metadataJson,
            Stream inputStream)
        {
            return UploadStream(
                host,
                PortToInt(port),
                useSsl,
                caseId,
                sessionId,
                collectionToken,
                artifactType,
                fileName,
                ULongToLong(fileSize),
                sha256,
                metadataJson,
                inputStream);
        }

        public string UploadStream(
            string host,
            int port,
            bool useSsl,
            string caseId,
            string sessionId,
            string collectionToken,
            string artifactType,
            string fileName,
            long fileSize,
            string sha256,
            string metadataJson,
            Stream inputStream)
        {
            ClearState();

            if (IsBlank(host) || IsBlank(caseId) || IsBlank(sessionId) || IsBlank(collectionToken)
                || IsBlank(artifactType) || inputStream == null)
            {
                return ErrorJson("invalid_argument", "host, caseId, sessionId, collectionToken, artifactType, and inputStream are required.");
            }

            if (fileSize < 0)
            {
                return ErrorJson("invalid_argument", "fileSize must be zero or greater.");
            }

            string metadata = NormalizeJsonObject(metadataJson);
            string profileId = GetCollectionProfileId();
            string initUrl = BuildUrl(host, port, useSsl, "/api/v1/collector/encase/uploads/init");
            string initBody =
                "{"
                + "\"session_id\":\"" + JsonEscape(sessionId) + "\","
                + "\"collection_token\":\"" + JsonEscape(collectionToken) + "\","
                + "\"case_id\":\"" + JsonEscape(caseId) + "\","
                + "\"file_name\":\"" + JsonEscape(IsBlank(fileName) ? "encase_entry" : fileName) + "\","
                + "\"file_size\":" + fileSize.ToString(CultureInfo.InvariantCulture) + ","
                + "\"file_hash\":" + JsonStringOrNull(sha256) + ","
                + "\"artifact_type\":\"" + JsonEscape(artifactType) + "\","
                + "\"content_type\":\"application/octet-stream\","
                + "\"profile_id\":" + JsonStringOrNull(profileId) + ","
                + "\"metadata\":" + metadata
                + "}";

            string initResponse = PostJson(initUrl, initBody);
            if (!LastSucceeded)
            {
                return initResponse;
            }

            string uploadUrl = JsonString(initResponse, "upload_url");
            string completeUrl = JsonString(initResponse, "complete_url");
            string ticket = JsonString(initResponse, "upload_ticket");
            if (IsBlank(uploadUrl) || IsBlank(completeUrl) || IsBlank(ticket))
            {
                return ErrorJson("invalid_init_response", "Upload init response did not include upload_url, complete_url, and upload_ticket.");
            }

            string dataUrl = BuildUrl(host, port, useSsl, uploadUrl);
            string dataResponse = PutStream(dataUrl, inputStream, fileSize, ticket);
            if (!LastSucceeded)
            {
                return dataResponse;
            }

            string completeBody =
                "{"
                + "\"session_id\":\"" + JsonEscape(sessionId) + "\","
                + "\"collection_token\":\"" + JsonEscape(collectionToken) + "\","
                + "\"case_id\":\"" + JsonEscape(caseId) + "\""
                + "}";

            string finalUrl = BuildUrl(host, port, useSsl, completeUrl);
            return PostJson(finalUrl, completeBody, ticket);
        }

        private static void ConfigureTls()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.Expect100Continue = false;
        }

        private string PostJson(string url, string json)
        {
            byte[] body = Encoding.UTF8.GetBytes(json);
            HttpWebRequest request = CreateRequest(url, "POST", "application/json");
            request.Accept = "application/json";
            request.ContentLength = body.Length;

            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(body, 0, body.Length);
            }

            return ReadResponse(request);
        }

        private string PostJson(string url, string json, string uploadTicket)
        {
            return PostJson(url, json, uploadTicket, null, null);
        }

        private string PostJson(string url, string json, string uploadTicket, string sessionId, string collectionToken)
        {
            byte[] body = Encoding.UTF8.GetBytes(json);
            HttpWebRequest request = CreateRequest(url, "POST", "application/json");
            request.Accept = "application/json";
            if (!IsBlank(uploadTicket))
            {
                request.Headers["X-EnCase-Upload-Ticket"] = uploadTicket;
            }
            if (!IsBlank(sessionId))
            {
                request.Headers["X-Session-ID"] = sessionId;
            }
            if (!IsBlank(collectionToken))
            {
                request.Headers["X-Collection-Token"] = collectionToken;
            }
            request.ContentLength = body.Length;

            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(body, 0, body.Length);
            }

            return ReadResponse(request);
        }

        private string GetJson(string url)
        {
            HttpWebRequest request = CreateRequest(url, "GET", "application/json");
            request.Accept = "application/json";
            return ReadResponse(request);
        }

        private string PutStream(string url, Stream inputStream, long contentLength)
        {
            return PutStream(url, inputStream, contentLength, null);
        }

        private string PutStream(string url, Stream inputStream, long contentLength, string uploadTicket)
        {
            int timeoutMs = ComputeUploadTimeoutMilliseconds(contentLength);
            HttpWebRequest request = CreateRequest(url, "PUT", "application/octet-stream", timeoutMs);
            request.Accept = "application/json";
            if (!IsBlank(uploadTicket))
            {
                request.Headers["X-EnCase-Upload-Ticket"] = uploadTicket;
            }
            request.ContentLength = contentLength;

            using (Stream output = request.GetRequestStream())
            {
                CopyStream(inputStream, output);
            }

            return ReadResponse(request);
        }

        private static HttpWebRequest CreateRequest(string url, string method, string contentType)
        {
            return CreateRequest(url, method, contentType, 120000);
        }

        private static HttpWebRequest CreateRequest(string url, string method, string contentType, int timeoutMs)
        {
            ConfigureTls();

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method;
            request.ContentType = contentType;
            request.UserAgent = "unJaena-EnCase-DotNet/1.0";
            request.Timeout = timeoutMs;
            request.ReadWriteTimeout = timeoutMs;
            request.KeepAlive = false;
            request.AllowAutoRedirect = false;
            return request;
        }

        private static int ComputeUploadTimeoutMilliseconds(long contentLength)
        {
            const int minTimeoutMs = 120000;
            const int maxTimeoutMs = 30 * 60 * 1000;
            const long conservativeBytesPerSecond = 256L * 1024L;

            if (contentLength <= 0)
            {
                return minTimeoutMs;
            }

            long estimatedSeconds = (contentLength / conservativeBytesPerSecond) + 300L;
            long estimatedMs = estimatedSeconds * 1000L;
            if (estimatedMs < minTimeoutMs) return minTimeoutMs;
            if (estimatedMs > maxTimeoutMs) return maxTimeoutMs;
            return (int)estimatedMs;
        }

        private static int PortToInt(uint port)
        {
            if (port > int.MaxValue)
            {
                return -1;
            }

            return (int)port;
        }

        private static long ULongToLong(ulong value)
        {
            if (value > long.MaxValue)
            {
                return -1L;
            }

            return (long)value;
        }

        private string ReadResponse(HttpWebRequest request)
        {
            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    return ReadHttpResponse(response);
                }
            }
            catch (WebException ex)
            {
                LastError = ex.Message;
                HttpWebResponse response = ex.Response as HttpWebResponse;
                if (response == null)
                {
                    LastSucceeded = false;
                    LastStatusCode = 0;
                    return ErrorJson("network_error", ex.Message);
                }

                using (response)
                {
                    return ReadHttpResponse(response);
                }
            }
            catch (Exception ex)
            {
                LastSucceeded = false;
                LastStatusCode = 0;
                LastError = ex.Message;
                return ErrorJson("unexpected_error", ex.Message);
            }
        }

        private string ReadHttpResponse(HttpWebResponse response)
        {
            LastStatusCode = (int)response.StatusCode;
            LastSucceeded = LastStatusCode >= 200 && LastStatusCode < 300;

            Stream responseStream = response.GetResponseStream();
            if (responseStream == null)
            {
                return string.Empty;
            }

            using (StreamReader reader = new StreamReader(responseStream, Encoding.UTF8))
            {
                string body = reader.ReadToEnd();
                if (!LastSucceeded)
                {
                    LastError = ResponseErrorSummary(body);
                }
                return body;
            }
        }

        private static void CopyStream(Stream input, Stream output)
        {
            byte[] buffer = new byte[1024 * 1024];
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, read);
            }
            output.Flush();
        }

        private static string BuildUrl(string host, int port, bool useSsl, string pathAndQuery)
        {
            if (pathAndQuery != null
                && (pathAndQuery.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                    || pathAndQuery.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
            {
                Uri absolute = new Uri(pathAndQuery);
                string expectedScheme = useSsl ? "https" : "http";
                bool expectedDefaultPort = (useSsl && port == 443) || (!useSsl && port == 80) || port <= 0;
                int expectedPort = expectedDefaultPort ? (useSsl ? 443 : 80) : port;
                int actualPort = absolute.IsDefaultPort ? (absolute.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80) : absolute.Port;
                if (!absolute.Scheme.Equals(expectedScheme, StringComparison.OrdinalIgnoreCase)
                    || !absolute.Host.Equals(host, StringComparison.OrdinalIgnoreCase)
                    || actualPort != expectedPort)
                {
                    throw new InvalidOperationException("Refusing cross-host collector URL.");
                }
                return absolute.ToString();
            }

            string scheme = useSsl ? "https" : "http";
            bool defaultPort = (useSsl && port == 443) || (!useSsl && port == 80);
            string authority = defaultPort || port <= 0
                ? host
                : host + ":" + port.ToString(CultureInfo.InvariantCulture);

            if (string.IsNullOrEmpty(pathAndQuery))
            {
                pathAndQuery = "/";
            }

            if (!pathAndQuery.StartsWith("/", StringComparison.Ordinal))
            {
                pathAndQuery = "/" + pathAndQuery;
            }

            return scheme + "://" + authority + pathAndQuery;
        }

        private static string ResponseErrorSummary(string body)
        {
            if (IsBlank(body))
            {
                return "HTTP request failed";
            }
            string compact = body.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ").Trim();
            while (compact.IndexOf("  ", StringComparison.Ordinal) >= 0)
            {
                compact = compact.Replace("  ", " ");
            }
            return compact.Length > 600 ? compact.Substring(0, 600) : compact;
        }

        private static string JsonEscape(string value)
        {
            if (value == null)
            {
                return string.Empty;
            }

            return value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
        }

        private static string JsonStringOrNull(string value)
        {
            return IsBlank(value) ? "null" : "\"" + JsonEscape(value) + "\"";
        }

        private static string NormalizeJsonObject(string json)
        {
            if (IsBlank(json))
            {
                return "{}";
            }

            string trimmed = json.Trim();
            if (!trimmed.StartsWith("{", StringComparison.Ordinal) || !trimmed.EndsWith("}", StringComparison.Ordinal))
            {
                return "{}";
            }

            return trimmed;
        }

        private static string JsonString(string json, string key)
        {
            if (json == null || key == null)
            {
                return string.Empty;
            }

            string needle = "\"" + key + "\"";
            int pos = json.IndexOf(needle, StringComparison.Ordinal);
            if (pos < 0)
            {
                return string.Empty;
            }

            pos = json.IndexOf(':', pos + needle.Length);
            if (pos < 0)
            {
                return string.Empty;
            }

            pos = json.IndexOf('"', pos + 1);
            if (pos < 0)
            {
                return string.Empty;
            }

            StringBuilder output = new StringBuilder();
            bool escaped = false;
            for (int i = pos + 1; i < json.Length; i++)
            {
                char ch = json[i];
                if (escaped)
                {
                    switch (ch)
                    {
                        case '"':
                        case '\\':
                        case '/':
                            output.Append(ch);
                            break;
                        case 'b':
                            output.Append('\b');
                            break;
                        case 'f':
                            output.Append('\f');
                            break;
                        case 'n':
                            output.Append('\n');
                            break;
                        case 'r':
                            output.Append('\r');
                            break;
                        case 't':
                            output.Append('\t');
                            break;
                        default:
                            output.Append(ch);
                            break;
                    }
                    escaped = false;
                    continue;
                }

                if (ch == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (ch == '"')
                {
                    return output.ToString();
                }

                output.Append(ch);
            }

            return string.Empty;
        }

        private static bool JsonBool(string json, string key)
        {
            if (json == null || key == null)
            {
                return false;
            }

            string needle = "\"" + key + "\"";
            int pos = json.IndexOf(needle, StringComparison.Ordinal);
            if (pos < 0)
            {
                return false;
            }

            pos = json.IndexOf(':', pos + needle.Length);
            if (pos < 0)
            {
                return false;
            }

            pos++;
            while (pos < json.Length && char.IsWhiteSpace(json[pos]))
            {
                pos++;
            }

            return pos + 4 <= json.Length
                && string.Compare(json, pos, "true", 0, 4, StringComparison.OrdinalIgnoreCase) == 0;
        }

        private static string JsonStringArray(string json, string key)
        {
            if (json == null || key == null)
            {
                return string.Empty;
            }

            string needle = "\"" + key + "\"";
            int pos = json.IndexOf(needle, StringComparison.Ordinal);
            if (pos < 0)
            {
                return string.Empty;
            }

            pos = json.IndexOf(':', pos + needle.Length);
            if (pos < 0)
            {
                return string.Empty;
            }

            int start = json.IndexOf('[', pos + 1);
            if (start < 0)
            {
                return string.Empty;
            }

            bool inString = false;
            bool escaped = false;
            for (int i = start; i < json.Length; i++)
            {
                char ch = json[i];
                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (ch == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (ch == '"')
                {
                    inString = !inString;
                    continue;
                }

                if (!inString && ch == ']')
                {
                    return json.Substring(start, i - start + 1);
                }
            }

            return string.Empty;
        }

        private static CollectionProfileTarget[] ParseCollectionProfileTargets(string json)
        {
            string targetsJson = JsonArray(json, "targets");
            List<string> objects = JsonObjectsInArray(targetsJson);
            List<CollectionProfileTarget> targets = new List<CollectionProfileTarget>();
            for (int i = 0; i < objects.Count; i++)
            {
                string item = objects[i];
                string artifactType = JsonString(item, "artifact_type");
                string[] patterns = ParseJsonStringArray(JsonStringArray(item, "patterns"));
                if (IsBlank(artifactType) || patterns.Length == 0)
                {
                    continue;
                }
                CollectionProfileTarget target = new CollectionProfileTarget();
                target.ArtifactType = artifactType;
                target.Kind = JsonString(item, "kind");
                target.Patterns = patterns;
                target.MaxBytes = JsonLong(item, "max_bytes", -1L);
                targets.Add(target);
            }
            return targets.ToArray();
        }

        private static string JsonArray(string json, string key)
        {
            if (json == null || key == null)
            {
                return string.Empty;
            }

            string needle = "\"" + key + "\"";
            int pos = json.IndexOf(needle, StringComparison.Ordinal);
            if (pos < 0)
            {
                return string.Empty;
            }

            pos = json.IndexOf(':', pos + needle.Length);
            if (pos < 0)
            {
                return string.Empty;
            }

            int start = json.IndexOf('[', pos + 1);
            if (start < 0)
            {
                return string.Empty;
            }

            bool inString = false;
            bool escaped = false;
            int depth = 0;
            for (int i = start; i < json.Length; i++)
            {
                char ch = json[i];
                if (escaped)
                {
                    escaped = false;
                    continue;
                }
                if (ch == '\\')
                {
                    escaped = true;
                    continue;
                }
                if (ch == '"')
                {
                    inString = !inString;
                    continue;
                }
                if (inString)
                {
                    continue;
                }
                if (ch == '[')
                {
                    depth++;
                    continue;
                }
                if (ch == ']')
                {
                    depth--;
                    if (depth == 0)
                    {
                        return json.Substring(start, i - start + 1);
                    }
                }
            }
            return string.Empty;
        }

        private static List<string> JsonObjectsInArray(string jsonArray)
        {
            List<string> objects = new List<string>();
            if (IsBlank(jsonArray))
            {
                return objects;
            }

            bool inString = false;
            bool escaped = false;
            int depth = 0;
            int start = -1;
            for (int i = 0; i < jsonArray.Length; i++)
            {
                char ch = jsonArray[i];
                if (escaped)
                {
                    escaped = false;
                    continue;
                }
                if (ch == '\\')
                {
                    escaped = true;
                    continue;
                }
                if (ch == '"')
                {
                    inString = !inString;
                    continue;
                }
                if (inString)
                {
                    continue;
                }
                if (ch == '{')
                {
                    if (depth == 0)
                    {
                        start = i;
                    }
                    depth++;
                    continue;
                }
                if (ch == '}')
                {
                    depth--;
                    if (depth == 0 && start >= 0)
                    {
                        objects.Add(jsonArray.Substring(start, i - start + 1));
                        start = -1;
                    }
                }
            }
            return objects;
        }

        private static string[] ParseJsonStringArray(string jsonArray)
        {
            List<string> values = new List<string>();
            if (IsBlank(jsonArray))
            {
                return values.ToArray();
            }

            bool inString = false;
            bool escaped = false;
            StringBuilder current = new StringBuilder();
            for (int i = 0; i < jsonArray.Length; i++)
            {
                char ch = jsonArray[i];
                if (!inString)
                {
                    if (ch == '"')
                    {
                        inString = true;
                        current.Length = 0;
                    }
                    continue;
                }

                if (escaped)
                {
                    switch (ch)
                    {
                        case '"':
                        case '\\':
                        case '/':
                            current.Append(ch);
                            break;
                        case 'b':
                            current.Append('\b');
                            break;
                        case 'f':
                            current.Append('\f');
                            break;
                        case 'n':
                            current.Append('\n');
                            break;
                        case 'r':
                            current.Append('\r');
                            break;
                        case 't':
                            current.Append('\t');
                            break;
                        default:
                            current.Append(ch);
                            break;
                    }
                    escaped = false;
                    continue;
                }
                if (ch == '\\')
                {
                    escaped = true;
                    continue;
                }
                if (ch == '"')
                {
                    values.Add(current.ToString());
                    inString = false;
                    continue;
                }
                current.Append(ch);
            }
            return values.ToArray();
        }

        private static long JsonLong(string json, string key, long defaultValue)
        {
            if (json == null || key == null)
            {
                return defaultValue;
            }

            string needle = "\"" + key + "\"";
            int pos = json.IndexOf(needle, StringComparison.Ordinal);
            if (pos < 0)
            {
                return defaultValue;
            }
            pos = json.IndexOf(':', pos + needle.Length);
            if (pos < 0)
            {
                return defaultValue;
            }
            pos++;
            while (pos < json.Length && char.IsWhiteSpace(json[pos]))
            {
                pos++;
            }
            if (pos + 4 <= json.Length && string.Compare(json, pos, "null", 0, 4, StringComparison.OrdinalIgnoreCase) == 0)
            {
                return defaultValue;
            }

            int end = pos;
            while (end < json.Length && (char.IsDigit(json[end]) || json[end] == '-'))
            {
                end++;
            }
            long parsed;
            if (end > pos && long.TryParse(json.Substring(pos, end - pos), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed))
            {
                return parsed;
            }
            return defaultValue;
        }

        private static string NormalizeMatchValue(string value)
        {
            if (value == null)
            {
                return string.Empty;
            }
            string result = value.Trim().Replace('\\', '/').ToLowerInvariant();
            while (result.IndexOf("//", StringComparison.Ordinal) >= 0)
            {
                result = result.Replace("//", "/");
            }
            return result;
        }

        private static string[] ExpandCollectionPatternVariants(string pattern)
        {
            string normalized = NormalizeMatchValue(pattern);
            List<string> variants = new List<string>();
            AddPatternVariant(variants, normalized);
            AddWindowsEnvPatternVariant(variants, normalized, "%userprofile%", "c:/users/*");
            AddWindowsEnvPatternVariant(variants, normalized, "%appdata%", "c:/users/*/appdata/roaming");
            AddWindowsEnvPatternVariant(variants, normalized, "%localappdata%", "c:/users/*/appdata/local");
            AddWindowsEnvPatternVariant(variants, normalized, "%programdata%", "c:/programdata");
            AddWindowsEnvPatternVariant(variants, normalized, "%public%", "c:/users/public");
            AddWindowsEnvPatternVariant(variants, normalized, "%temp%", "c:/users/*/appdata/local/temp");
            AddWindowsEnvPatternVariant(variants, normalized, "%tmp%", "c:/users/*/appdata/local/temp");

            int count = variants.Count;
            for (int i = 0; i < count; i++)
            {
                AddDirectFilePatternVariant(variants, variants[i]);
                AddWindowsUserDriveOptionalPatternVariants(variants, variants[i]);
            }
            return variants.ToArray();
        }

        private static void AddWindowsEnvPatternVariant(List<string> variants, string pattern, string token, string replacement)
        {
            if (IsBlank(pattern) || pattern.IndexOf(token, StringComparison.OrdinalIgnoreCase) < 0)
            {
                return;
            }
            AddPatternVariant(variants, pattern.Replace(token, replacement));
        }

        private static void AddDirectFilePatternVariant(List<string> variants, string pattern)
        {
            if (IsBlank(pattern) || pattern.IndexOf("/**/", StringComparison.Ordinal) < 0)
            {
                return;
            }
            AddPatternVariant(variants, pattern.Replace("/**/", "/"));
        }

        private static void AddWindowsUserDriveOptionalPatternVariants(List<string> variants, string pattern)
        {
            string normalized = NormalizeMatchValue(pattern);
            string suffix = null;
            if (normalized.StartsWith("c:/users/", StringComparison.Ordinal))
            {
                suffix = normalized.Substring(3);
            }
            else if (normalized.StartsWith("c:/documents and settings/", StringComparison.Ordinal))
            {
                suffix = normalized.Substring(3);
            }
            if (!IsBlank(suffix))
            {
                AddPatternVariant(variants, suffix);
                AddPatternVariant(variants, "/" + suffix);
            }
        }

        private static void AddPatternVariant(List<string> variants, string pattern)
        {
            string normalized = NormalizeMatchValue(pattern);
            if (IsBlank(normalized))
            {
                return;
            }
            for (int i = 0; i < variants.Count; i++)
            {
                if (string.Compare(variants[i], normalized, StringComparison.Ordinal) == 0)
                {
                    return;
                }
            }
            variants.Add(normalized);
        }

        private static string PathLeaf(string path)
        {
            if (IsBlank(path))
            {
                return string.Empty;
            }
            string normalized = NormalizeMatchValue(path);
            int last = normalized.LastIndexOf('/');
            if (last >= 0 && last + 1 < normalized.Length)
            {
                return normalized.Substring(last + 1);
            }
            return normalized;
        }

        private static bool WildcardMatch(string text, string pattern)
        {
            if (text == null || pattern == null)
            {
                return false;
            }

            try
            {
                string regex = "^" + WildcardPatternToRegex(pattern) + "$";
                return Regex.IsMatch(text, regex, RegexOptions.CultureInvariant);
            }
            catch
            {
                return false;
            }
        }

        private static string WildcardPatternToRegex(string pattern)
        {
            StringBuilder regex = new StringBuilder();
            for (int i = 0; i < pattern.Length; i++)
            {
                char ch = pattern[i];
                if (ch == '*')
                {
                    regex.Append(".*");
                    continue;
                }
                if (ch == '?')
                {
                    regex.Append('.');
                    continue;
                }
                if (ch == '[')
                {
                    int end = FindCharacterClassEnd(pattern, i + 1);
                    if (end > i + 1)
                    {
                        regex.Append(ConvertCharacterClassToRegex(pattern.Substring(i + 1, end - i - 1)));
                        i = end;
                        continue;
                    }
                }
                regex.Append(Regex.Escape(ch.ToString()));
            }
            return regex.ToString();
        }

        private static int FindCharacterClassEnd(string pattern, int start)
        {
            for (int i = start; i < pattern.Length; i++)
            {
                if (pattern[i] == ']')
                {
                    return i;
                }
            }
            return -1;
        }

        private static string ConvertCharacterClassToRegex(string value)
        {
            StringBuilder result = new StringBuilder();
            result.Append('[');
            int start = 0;
            if (value.Length > 0 && (value[0] == '!' || value[0] == '^'))
            {
                result.Append('^');
                start = 1;
            }
            for (int i = start; i < value.Length; i++)
            {
                char ch = value[i];
                if (ch == '\\')
                {
                    result.Append("\\\\");
                }
                else if (ch == ']')
                {
                    result.Append("\\]");
                }
                else if (ch == '^' && i == start)
                {
                    result.Append("\\^");
                }
                else
                {
                    result.Append(ch);
                }
            }
            result.Append(']');
            return result.ToString();
        }

        private string ErrorJson(string error, string message)
        {
            LastSucceeded = false;
            if (LastStatusCode == 0 || (LastStatusCode >= 200 && LastStatusCode < 300))
            {
                LastStatusCode = -1;
            }
            LastError = message;
            return "{\"success\":false,\"error\":\"" + JsonEscape(error) + "\",\"message\":\"" + JsonEscape(message) + "\"}";
        }

        private void ClearState()
        {
            LastStatusCode = 0;
            LastError = string.Empty;
            LastSucceeded = false;
        }

        private static bool IsBlank(string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }
    }
}
