extern alias ConfigLib;

// Bridges the aliased production assembly into a global type alias to avoid
// ambiguity between the ConfigurationHelper type and the test namespace path.
global using ConfigurationHelperClass = ConfigLib::Pepperdine.Helpers.ConfigurationHelper;
