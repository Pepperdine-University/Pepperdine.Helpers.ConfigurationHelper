using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Configuration;
using Xunit;
using ConfigurationHelperClass = Pepperdine.Helpers.ConfigurationHelper;

namespace ConfigurationHelper.Tests;

[SupportedOSPlatform("windows")]
public sealed class ConfigurationHelperTests
{
    private const string PLAIN_KEY = "PlainKey";
    private const string PLAIN_VALUE = "PlainValue";
    private const string MISSING_KEY = "MissingKey";
    private const string MISSING_KEY_MESSAGE = "No value found for the key 'MissingKey'";
    private const string MY_SECRET_KEY = "MySecretKey";
    private const string MY_SECRET_VALUE = "SuperSecretPassword123";
    private const string CONNECTION_STRING_KEY = "ConnectionStrings:Db";
    private const string CONNECTION_STRING_VALUE = "Server=myserver;Database=mydb;User=myuser;Password=mypassword";
    private const string ALREADY_ENCRYPTED_KEY = "EncryptedKey";
    private const string ALREADY_ENCRYPTED_VALUE = "AlreadyEncryptedSecret";
    private const string EMPTY_SECRET_KEY = "EmptySecret";
    private const string WHITESPACE_SECRET_KEY = "WhitespaceSecret";
    private const string EXISTING_ENCRYPTED_SECRET_KEY = "ExistingEncryptedSecret";
    private const string EXISTING_ENCRYPTED_SECRET_VALUE = "ExistingSecretValue";
    private const string NEW_PLAIN_SECRET_KEY = "NewPlainSecret";
    private const string NEW_PLAIN_SECRET_VALUE = "FreshSecretValue";
    private const string MALFORMED_KEY = "MalformedKey";
    private const string MALFORMED_VALUE = "%%% definitely-not-base64 %%%";
    private const string WHITESPACE_SECRET_VALUE = "   ";
    private const string APP_SETTINGS_SECRETS_FILE_NAME = "appsettings.secrets.json";

    [Fact]
    public void GetValue_ReturnsPlainConfigurationValue()
    {
        using var scope = new TempWorkingDirectoryScope();

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [PLAIN_KEY] = PLAIN_VALUE
            })
            .Build();

        string value = ConfigurationHelperClass.GetValue(PLAIN_KEY);

        Assert.Equal(PLAIN_VALUE, value);
    }

    [Fact]
    public void GetValue_ThrowsWhenKeyIsMissing()
    {
        using var scope = new TempWorkingDirectoryScope();

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        KeyNotFoundException ex = Assert.Throws<KeyNotFoundException>(() => ConfigurationHelperClass.GetValue(MISSING_KEY));

        Assert.Equal(MISSING_KEY_MESSAGE, ex.Message);
    }

    [Fact]
    public void Configuration_EncryptsPlaintextSecretsFile_AndReturnsPlaintextValues()
    {
        using var scope = new TempWorkingDirectoryScope();
        string secretsPath = Path.Combine(scope.DirectoryPath, APP_SETTINGS_SECRETS_FILE_NAME);

        File.WriteAllText(
            secretsPath,
            $$"""
            {
              "{{MY_SECRET_KEY}}": "{{MY_SECRET_VALUE}}",
              "ConnectionStrings": {
                "Db": "{{CONNECTION_STRING_VALUE}}"
              }
            }
            """);

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        string encryptedJson = File.ReadAllText(secretsPath);

        Assert.DoesNotContain(MY_SECRET_VALUE, encryptedJson);
        Assert.DoesNotContain(CONNECTION_STRING_VALUE, encryptedJson);
        Assert.Equal(MY_SECRET_VALUE, ConfigurationHelperClass.GetValue(MY_SECRET_KEY));
        Assert.Equal(
            CONNECTION_STRING_VALUE,
            ConfigurationHelperClass.GetValue(CONNECTION_STRING_KEY));
    }

    [Fact]
    public void Configuration_LoadsAlreadyEncryptedSecretsWithoutRewritingValues()
    {
        using var scope = new TempWorkingDirectoryScope();
        string secretsPath = Path.Combine(scope.DirectoryPath, APP_SETTINGS_SECRETS_FILE_NAME);

        string encryptedSecret = Protect(ALREADY_ENCRYPTED_VALUE);
        File.WriteAllText(
            secretsPath,
            $$"""
            {
              "{{ALREADY_ENCRYPTED_KEY}}": "{{encryptedSecret}}"
            }
            """);

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        string jsonAfterLoad = File.ReadAllText(secretsPath);

        Assert.Contains(encryptedSecret, jsonAfterLoad);
        Assert.Equal(ALREADY_ENCRYPTED_VALUE, ConfigurationHelperClass.GetValue(ALREADY_ENCRYPTED_KEY));
    }

    [Fact]
    public void Configuration_LeavesBlankAndWhitespaceSecretValuesUntouched()
    {
        using var scope = new TempWorkingDirectoryScope();
        string secretsPath = Path.Combine(scope.DirectoryPath, APP_SETTINGS_SECRETS_FILE_NAME);

        File.WriteAllText(
            secretsPath,
            $$"""
            {
              "{{EMPTY_SECRET_KEY}}": "",
              "{{WHITESPACE_SECRET_KEY}}": "{{WHITESPACE_SECRET_VALUE}}"
            }
            """);

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        string jsonAfterLoad = File.ReadAllText(secretsPath);

        Assert.Contains($@"""{EMPTY_SECRET_KEY}"": """"", jsonAfterLoad);
        Assert.Contains($@"""{WHITESPACE_SECRET_KEY}"": ""{WHITESPACE_SECRET_VALUE}""", jsonAfterLoad);
        Assert.Throws<ArgumentException>(() => ConfigurationHelperClass.GetValue(EMPTY_SECRET_KEY));
        Assert.Throws<ArgumentException>(() => ConfigurationHelperClass.GetValue(WHITESPACE_SECRET_KEY));
    }

    [Fact]
    public void GetValue_ReturnsOriginalValue_WhenConfiguredValueIsMalformedBase64()
    {
        using var scope = new TempWorkingDirectoryScope();

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [MALFORMED_KEY] = MALFORMED_VALUE
            })
            .Build();

        string value = ConfigurationHelperClass.GetValue(MALFORMED_KEY);

        Assert.Equal(MALFORMED_VALUE, value);
    }

    [Fact]
    public void Configuration_EncryptsOnlyNewPlaintextValues_WhenFileContainsMixedSecrets()
    {
        using var scope = new TempWorkingDirectoryScope();
        string secretsPath = Path.Combine(scope.DirectoryPath, APP_SETTINGS_SECRETS_FILE_NAME);

        string existingEncryptedSecret = Protect(EXISTING_ENCRYPTED_SECRET_VALUE);
        File.WriteAllText(
            secretsPath,
            $$"""
            {
              "{{EXISTING_ENCRYPTED_SECRET_KEY}}": "{{existingEncryptedSecret}}",
              "{{NEW_PLAIN_SECRET_KEY}}": "{{NEW_PLAIN_SECRET_VALUE}}",
              "{{EMPTY_SECRET_KEY}}": "",
              "{{WHITESPACE_SECRET_KEY}}": "{{WHITESPACE_SECRET_VALUE}}"
            }
            """);

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        string jsonAfterLoad = File.ReadAllText(secretsPath);

        Assert.Contains(existingEncryptedSecret, jsonAfterLoad);
        Assert.DoesNotContain(NEW_PLAIN_SECRET_VALUE, jsonAfterLoad);
        Assert.Contains($@"""{EMPTY_SECRET_KEY}"": """"", jsonAfterLoad);
        Assert.Contains($@"""{WHITESPACE_SECRET_KEY}"": ""{WHITESPACE_SECRET_VALUE}""", jsonAfterLoad);
        Assert.Equal(EXISTING_ENCRYPTED_SECRET_VALUE, ConfigurationHelperClass.GetValue(EXISTING_ENCRYPTED_SECRET_KEY));
        Assert.Equal(NEW_PLAIN_SECRET_VALUE, ConfigurationHelperClass.GetValue(NEW_PLAIN_SECRET_KEY));
        Assert.Throws<ArgumentException>(() => ConfigurationHelperClass.GetValue(EMPTY_SECRET_KEY));
        Assert.Throws<ArgumentException>(() => ConfigurationHelperClass.GetValue(WHITESPACE_SECRET_KEY));
    }

    private static string Protect(string value)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(value);
        byte[] encrypted = ProtectedData.Protect(plainBytes, null, DataProtectionScope.LocalMachine);
        return Convert.ToBase64String(encrypted);
    }

    private sealed class TempWorkingDirectoryScope : IDisposable
    {
        private readonly string _originalDirectory = Environment.CurrentDirectory;
        private readonly string _secretsPath;
        private readonly string? _originalSecretsContent;

        public TempWorkingDirectoryScope()
        {
            DirectoryPath = AppContext.BaseDirectory;
            _secretsPath = Path.Combine(DirectoryPath, APP_SETTINGS_SECRETS_FILE_NAME);
            _originalSecretsContent = File.Exists(_secretsPath) ? File.ReadAllText(_secretsPath) : null;
            Environment.CurrentDirectory = DirectoryPath;
        }

        public string DirectoryPath { get; }

        public void Dispose()
        {
            ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

            Environment.CurrentDirectory = _originalDirectory;

            if (_originalSecretsContent is null)
            {
                if (File.Exists(_secretsPath))
                {
                    File.Delete(_secretsPath);
                }
            }
            else
            {
                File.WriteAllText(_secretsPath, _originalSecretsContent);
            }
        }
    }
}
