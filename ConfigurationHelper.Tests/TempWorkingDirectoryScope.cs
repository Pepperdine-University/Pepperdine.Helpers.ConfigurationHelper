namespace Pepperdine.Helpers.ConfigurationHelper.Tests;

[SupportedOSPlatform("windows")]
internal sealed class TempWorkingDirectoryScope : IDisposable
{
    private readonly string _originalDirectory;
    private readonly string _secretsPath;
    private readonly string? _originalSecretsContent;

    internal string DirectoryPath { get; }

    internal TempWorkingDirectoryScope()
    {
        _originalDirectory = Environment.CurrentDirectory;
        DirectoryPath = AppContext.BaseDirectory;
        _secretsPath = Path.Combine(
            DirectoryPath,
            ConfigurationHelperTest.APP_SETTINGS_SECRETS_FILE_NAME);
        _originalSecretsContent = File.Exists(_secretsPath) ? File.ReadAllText(_secretsPath) : null;
        Environment.CurrentDirectory = DirectoryPath;
    }

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

            return;
        }

        File.WriteAllText(_secretsPath, _originalSecretsContent);
    }
}
