namespace NetworkMonitor.Config;
internal class ConfigManager
{
    private readonly string configPath = "security_config.json";

    public SecurityConfig Load()
    {
        SecurityConfig configuration;

        try
        {
            if (File.Exists(configPath))
            {
                string json = File.ReadAllText(configPath);
                configuration = JsonSerializer.Deserialize<SecurityConfig>(json);

                if (configuration.KnownSuspiciousProcesses != null)
                {
                    configuration.KnownSuspiciousProcesses =
                        new Dictionary<string, string>(
                            configuration.KnownSuspiciousProcesses,
                            StringComparer.OrdinalIgnoreCase);
                }
            }
            else
            {
                configuration = CreateDefault();
            }
        }
        catch
        {
            configuration = CreateDefault();
        }

        return configuration;
    }

    public void Save(SecurityConfig configuration)
    {
        string json = JsonSerializer.Serialize(configuration, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(configPath, json);
    }

    private SecurityConfig CreateDefault()
    {
        SecurityConfig configuration = new SecurityConfig();
        configuration.WhitelistedPorts = new List<int>
        {
            80, 443, 53, 21, 22, 25, 110, 143,
            5432, 7680, 4767, 53241, 63342, 42050,
            135, 139, 445, 5040,
            49664, 49665, 49666, 49667, 49668, 49669, 49672,
            44321, 44350, 44380, 44399, 59717, 59719, 61989, 61994
        };

        configuration.WhitelistedProcesses = new List<string>
        {
            "chrome","firefox","edge","explorer","svchost","winlogon","services","system","postgres",
            "java","code","devenv","msedge","notepad","taskmgr","wininit","csrss","lsass","smss",
            "spoolsv","docker","node","python","php","pangps","embeddings-server","datagrip64",
            "com.docker.backend","onedrive.sync.service","jhi_service","slack"
        };

        configuration.KnownSuspiciousProcesses = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "PanGPS", "GlobalProtect VPN - Corporate software" },
            { "embeddings-server", "AI Service - Legitimate" },
            { "datagrip64", "JetBrains DataGrip - Legitimate IDE" },
            { "com.docker.backend", "Docker Desktop - Legitimate" },
            { "OneDrive.Sync.Service", "Microsoft OneDrive - Legitimate" },
            { "jhi_service", "Intel Service - Legitimate" }
        };

        configuration.CheckInterval = 5000;
        configuration.LogToFile = true;

        Save(configuration);
        return configuration;
    }
}
