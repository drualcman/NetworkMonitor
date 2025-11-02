namespace NetworkMonitor;
internal class SecurityConfig
{
    public List<int> WhitelistedPorts { get; set; }
    public List<string> WhitelistedProcesses { get; set; }
    public int CheckInterval { get; set; }
    public bool LogToFile { get; set; }
    public Dictionary<string, string> KnownSuspiciousProcesses { get; set; }
}
