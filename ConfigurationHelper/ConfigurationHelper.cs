using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Pepperdine.Helpers
{
    public class ConfigurationHelper
    {
        private const string SECRETS_FILE_PATH = "appsettings.secrets.json";

        private static readonly object _secretsFileLock = new();
        private static IConfigurationRoot _configuration = new ConfigurationBuilder().Build();

        /// <summary>
        /// Gets or sets the application's configuration.
        /// Setting this property will encrypt any unencrypted secrets found
        /// in the appsettings.secrets.json file and reload it into the configuration.
        /// </summary>
        public static IConfigurationRoot Configuration
        {
            get => _configuration;
            set
            {
                if (File.Exists(SECRETS_FILE_PATH))
                {
                    EncryptSettingsFile(SECRETS_FILE_PATH);
                }

                _configuration = new ConfigurationBuilder()
                    .AddConfiguration(value)
                    .AddJsonFile(SECRETS_FILE_PATH, optional: true, reloadOnChange: true)
                    .Build();
            }
        }

        /// <summary>
        /// Retrieves a configuration value by key.
        /// If the value is encrypted, it will be decrypted before returning.
        /// </summary>
        /// <param name="key">The configuration key to retrieve.</param>
        /// <returns>The plaintext configuration value.</returns>
        /// <exception cref="KeyNotFoundException">Thrown if the key does not exist in the configuration.</exception>
        public static string GetValue(string key)
        {
            string configValue = Configuration[key]
                                 ?? throw new KeyNotFoundException($"No value found for the key '{key}'");

            return TryDecrypt(configValue, out string decryptedValue)
                ? decryptedValue
                : configValue;
        }

        /// <summary>
        /// Encrypts any plaintext values found in the specified secrets file.
        /// </summary>
        /// <param name="filePath">The path to the secrets file.</param>
        private static void EncryptSettingsFile(string filePath)
        {
            lock (_secretsFileLock)
            {
                string jsonContent = File.ReadAllText(filePath);
                JToken jToken = JToken.Parse(jsonContent);

                bool jsonChanged = false;
                EncryptJsonToken(jToken, ref jsonChanged);

                if (jsonChanged)
                {
                    string updatedJson = JsonConvert.SerializeObject(jToken, Newtonsoft.Json.Formatting.Indented);
                    File.WriteAllText(filePath, updatedJson);
                }
            }
        }

        /// <summary>
        /// Recursively encrypts all string values in a JSON token that are not already encrypted.
        /// </summary>
        /// <param name="token">The JSON token to process.</param>
        /// <param name="encryptionApplied">True if any encryption was performed; otherwise, false.</param>
        private static void EncryptJsonToken(JToken token, ref bool encryptionApplied)
        {
            switch (token.Type)
            {
                case JTokenType.Object:
                    foreach (JProperty property in ((JObject)token).Properties())
                    {
                        EncryptJsonToken(property.Value, ref encryptionApplied);
                    }
                    break;
                case JTokenType.Array:
                    foreach (JToken item in (JArray)token)
                    {
                        EncryptJsonToken(item, ref encryptionApplied);
                    }
                    break;
                case JTokenType.String:
                    string? value = token.Value<string>();
                    if (!string.IsNullOrWhiteSpace(value) && !TryDecrypt(value, out _))
                    {
                        string? encrypted = Encrypt(value);
                        token.Replace(encrypted);
                        encryptionApplied = true;
                    }
                    break;
            }
        }

        /// <summary>
        /// Encrypts a plaintext string using Windows DPAPI with LocalMachine scope.
        /// </summary>
        /// <param name="value">The plaintext value to encrypt.</param>
        /// <returns>The encrypted value as a Base64 string, or the original value if null or whitespace.</returns>
        private static string? Encrypt(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return value;

            try
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(value);
                byte[] encrypted = ProtectedData.Protect(plainBytes, null, DataProtectionScope.LocalMachine);
                return Convert.ToBase64String(encrypted);
            }
            catch (Exception e)
            {
                throw new InvalidOperationException("Unexpected error occurred during encryption.", e);
            }
        }

        /// <summary>
        /// Attempts to decrypt an encrypted value.
        /// If decryption fails or the value is not encrypted, returns the original value.
        /// </summary>
        /// <param name="value">The value to decrypt.</param>
        /// <param name="decryptedValue">The decrypted value if successful, otherwise the original value.</param>
        /// <returns>True if decryption was successful; otherwise, false.</returns>
        private static bool TryDecrypt(string value, out string decryptedValue)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("Cannot decrypt a null or whitespace value.", nameof(value));
            }

            try
            {
                byte[] encryptedData = Convert.FromBase64String(value);
                byte[] decryptedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.LocalMachine);
                decryptedValue = Encoding.UTF8.GetString(decryptedData);
                return true;
            }
            catch
            {
                decryptedValue = value;
                return false;
            }
        }
    }
}
