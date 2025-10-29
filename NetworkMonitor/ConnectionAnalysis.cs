namespace NetworkMonitor;
public class ConnectionAnalysis
{
    public bool IsSuspicious { get; set; }
    public List<string> Reasons { get; set; } = new List<string>();
}
