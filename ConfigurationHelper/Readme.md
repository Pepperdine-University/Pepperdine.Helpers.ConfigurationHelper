# Pepperdine.Helpers.ConfigurationHelper

A .NET helper class that eases access to values in appsettings. It also securely manages secrets in `appsettings.secrets.json` by encrypting sensitive values on disk using Windows DPAPI (LocalMachine scope) while letting you retrieve plaintext at runtime.

---

## Features
- ✅ Access to appesettings values even from static methods
- ✅ Automatically encrypts plaintext secrets in your appsettings.secrets.json file
- ✅ DPAPI-based encryption scoped to the local machine
- ✅ Seamless integration with Microsoft.Extensions.Configuration
- ✅ Simple static access pattern

---

## Installation

Install from [NuGet.org](https://www.nuget.org/): search for Pepperdine.Helpers.ConfigurationHelper

CLI: 
dotnet add package Pepperdine.Helpers.ConfigurationHelper --version 1.0.2


## Usage

### 1. Example secrets file (`appsettings.secrets.json`)

```json
{
  "MySecretKey": "SuperSecretPassword123",
  "ConnectionStrings": {
    "Db": "Server=myserver;Database=mydb;User=myuser;Password=mypassword"
  }
}
```


###  2. Configure your `Program.cs`
```csharp
using Pepperdine.Helpers;
using Microsoft.Extensions.Configuration;

var builder = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

ConfigurationHelper.Configuration = builder.Build();
```
### 3. Access secrets in your code
```csharp
string mySecret = ConfigurationHelper.GetValue("MySecretKey");
string connectionString = ConfigurationHelper.GetValue("ConnectionStrings:Db");
```