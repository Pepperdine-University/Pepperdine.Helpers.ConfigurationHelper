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
    [Fact]
    public void GetValue_ReturnsPlainConfigurationValue()
    {
        using var scope = new TempWorkingDirectoryScope();

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PlainKey"] = "PlainValue"
            })
            .Build();

        string value = ConfigurationHelperClass.GetValue("PlainKey");

        Assert.Equal("PlainValue", value);
    }

    [Fact]
    public void GetValue_ThrowsWhenKeyIsMissing()
    {
        using var scope = new TempWorkingDirectoryScope();

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        KeyNotFoundException ex = Assert.Throws<KeyNotFoundException>(() => ConfigurationHelperClass.GetValue("MissingKey"));

        Assert.Equal("No value found for the key 'MissingKey'", ex.Message);
    }

    [Fact]
    public void Configuration_EncryptsPlaintextSecretsFile_AndReturnsPlaintextValues()
    {
        using var scope = new TempWorkingDirectoryScope();
        string secretsPath = Path.Combine(scope.DirectoryPath, "appsettings.secrets.json");

        File.WriteAllText(
            secretsPath,
            """
            {
              "MySecretKey": "SuperSecretPassword123",
              "ConnectionStrings": {
                "Db": "Server=myserver;Database=mydb;User=myuser;Password=mypassword"
              }
            }
            """);

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        string encryptedJson = File.ReadAllText(secretsPath);

        Assert.DoesNotContain("SuperSecretPassword123", encryptedJson);
        Assert.DoesNotContain("Server=myserver;Database=mydb;User=myuser;Password=mypassword", encryptedJson);
        Assert.Equal("SuperSecretPassword123", ConfigurationHelperClass.GetValue("MySecretKey"));
        Assert.Equal(
            "Server=myserver;Database=mydb;User=myuser;Password=mypassword",
            ConfigurationHelperClass.GetValue("ConnectionStrings:Db"));
    }

    [Fact]
    public void Configuration_LoadsAlreadyEncryptedSecretsWithoutRewritingValues()
    {
        using var scope = new TempWorkingDirectoryScope();
        string secretsPath = Path.Combine(scope.DirectoryPath, "appsettings.secrets.json");

        string encryptedSecret = Protect("AlreadyEncryptedSecret");
        File.WriteAllText(
            secretsPath,
            $$"""
            {
              "EncryptedKey": "{{encryptedSecret}}"
            }
            """);

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        string jsonAfterLoad = File.ReadAllText(secretsPath);

        Assert.Contains(encryptedSecret, jsonAfterLoad);
        Assert.Equal("AlreadyEncryptedSecret", ConfigurationHelperClass.GetValue("EncryptedKey"));
    }

    [Fact]
    public void Configuration_LeavesBlankAndWhitespaceSecretValuesUntouched()
    {
        using var scope = new TempWorkingDirectoryScope();
        string secretsPath = Path.Combine(scope.DirectoryPath, "appsettings.secrets.json");

        File.WriteAllText(
            secretsPath,
            """
            {
              "EmptySecret": "",
              "WhitespaceSecret": "   "
            }
            """);

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        string jsonAfterLoad = File.ReadAllText(secretsPath);

        Assert.Contains(@"""EmptySecret"": """"", jsonAfterLoad);
        Assert.Contains(@"""WhitespaceSecret"": ""   """, jsonAfterLoad);
        Assert.Throws<ArgumentException>(() => ConfigurationHelperClass.GetValue("EmptySecret"));
        Assert.Throws<ArgumentException>(() => ConfigurationHelperClass.GetValue("WhitespaceSecret"));
    }

    [Fact]
    public void GetValue_ReturnsOriginalValue_WhenConfiguredValueIsMalformedBase64()
    {
        using var scope = new TempWorkingDirectoryScope();

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MalformedKey"] = "%%% definitely-not-base64 %%%"
            })
            .Build();

        string value = ConfigurationHelperClass.GetValue("MalformedKey");

        Assert.Equal("%%% definitely-not-base64 %%%", value);
    }

    [Fact]
    public void Configuration_EncryptsOnlyNewPlaintextValues_WhenFileContainsMixedSecrets()
    {
        using var scope = new TempWorkingDirectoryScope();
        string secretsPath = Path.Combine(scope.DirectoryPath, "appsettings.secrets.json");

        string existingEncryptedSecret = Protect("ExistingSecretValue");
        File.WriteAllText(
            secretsPath,
            $$"""
            {
              "ExistingEncryptedSecret": "{{existingEncryptedSecret}}",
              "NewPlainSecret": "FreshSecretValue",
              "EmptySecret": "",
              "WhitespaceSecret": "   "
            }
            """);

        ConfigurationHelperClass.Configuration = new ConfigurationBuilder().Build();

        string jsonAfterLoad = File.ReadAllText(secretsPath);

        Assert.Contains(existingEncryptedSecret, jsonAfterLoad);
        Assert.DoesNotContain("FreshSecretValue", jsonAfterLoad);
        Assert.Contains(@"""EmptySecret"": """"", jsonAfterLoad);
        Assert.Contains(@"""WhitespaceSecret"": ""   """, jsonAfterLoad);
        Assert.Equal("ExistingSecretValue", ConfigurationHelperClass.GetValue("ExistingEncryptedSecret"));
        Assert.Equal("FreshSecretValue", ConfigurationHelperClass.GetValue("NewPlainSecret"));
        Assert.Throws<ArgumentException>(() => ConfigurationHelperClass.GetValue("EmptySecret"));
        Assert.Throws<ArgumentException>(() => ConfigurationHelperClass.GetValue("WhitespaceSecret"));
    }

    private static string Protect(string value)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(value);
        byte[] encrypted = ProtectedData.Protect(plainBytes, null, DataProtectionScope.LocalMachine);
        return Convert.ToBase64String(encrypted);
    }

    private sealed class TempWorkingDirectoryScope : IDisposable
    {
        private const string SecretsFileName = "appsettings.secrets.json";
        private readonly string _originalDirectory = Environment.CurrentDirectory;
        private readonly string _secretsPath;
        private readonly string? _originalSecretsContent;

        public TempWorkingDirectoryScope()
        {
            DirectoryPath = AppContext.BaseDirectory;
            _secretsPath = Path.Combine(DirectoryPath, SecretsFileName);
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
