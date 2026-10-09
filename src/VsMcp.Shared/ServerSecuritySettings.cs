using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json;
using VsMcp.Shared.Protocol;

namespace VsMcp.Shared
{
    /// <summary>
    /// Security settings for the extension's local HTTP server, read from
    /// %LOCALAPPDATA%\VsMcp\server-settings.json. A default file is created on first load.
    /// </summary>
    public class ServerSecuritySettings
    {
        public const string SettingsFileName = "server-settings.json";

        /// <summary>
        /// When true (default), every HTTP request must carry "Authorization: Bearer &lt;token&gt;",
        /// where the token is generated per VS session and written to the port file.
        /// </summary>
        [JsonProperty("requireAuthToken")]
        public bool RequireAuthToken { get; set; } = true;

        /// <summary>
        /// Browser origins (e.g. "http://localhost:5173") allowed to call the server.
        /// Requests carrying any other Origin header are rejected. "*" allows every origin.
        /// Empty (default) means browsers cannot call the server at all.
        /// </summary>
        [JsonProperty("allowedOrigins")]
        public List<string> AllowedOrigins { get; set; } = new List<string>();

        public static string GetSettingsPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                McpConstants.PortFileFolder,
                SettingsFileName);
        }

        /// <summary>
        /// Loads settings, writing a default file if none exists.
        /// Falls back to secure defaults if the file cannot be read or parsed.
        /// </summary>
        public static ServerSecuritySettings Load()
        {
            var path = GetSettingsPath();
            try
            {
                if (File.Exists(path))
                {
                    var settings = JsonConvert.DeserializeObject<ServerSecuritySettings>(File.ReadAllText(path));
                    if (settings != null)
                    {
                        settings.AllowedOrigins = settings.AllowedOrigins ?? new List<string>();
                        return settings;
                    }
                }
                else
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(path));
                    File.WriteAllText(path, JsonConvert.SerializeObject(new ServerSecuritySettings(), Formatting.Indented));
                }
            }
            catch { /* best effort - fall through to secure defaults */ }

            return new ServerSecuritySettings();
        }

        public bool IsOriginAllowed(string origin)
        {
            if (string.IsNullOrEmpty(origin))
                return false;

            foreach (var allowed in AllowedOrigins)
            {
                if (allowed == "*")
                    return true;
                if (!string.IsNullOrEmpty(allowed)
                    && string.Equals(allowed.TrimEnd('/'), origin.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Generates a random 256-bit token as a hex string.
        /// </summary>
        public static string GenerateToken()
        {
            var bytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        /// <summary>
        /// Compares two tokens in constant time (for equal lengths).
        /// </summary>
        public static bool TokensEqual(string expected, string actual)
        {
            if (expected == null || actual == null || expected.Length != actual.Length)
                return false;

            var diff = 0;
            for (var i = 0; i < expected.Length; i++)
            {
                diff |= expected[i] ^ actual[i];
            }
            return diff == 0;
        }
    }
}
