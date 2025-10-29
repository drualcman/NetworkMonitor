namespace NetworkMonitor;
public class NetworkConnection
{
    public IPEndPoint LocalEndPoint { get; set; }
    public IPEndPoint RemoteEndPoint { get; set; }
    public TcpState State { get; set; }
    public int ProcessId { get; set; }
}
