namespace NetworkMonitor.Analyzers;
internal class EstablishedConnectionsChecker : IAnalyzer
{
    private readonly AlertSoundPlayer alertPlayer = new AlertSoundPlayer();

    public void Analyze(SecurityConfig config, CancellationToken token)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("ESTABLISHED INCOMING CONNECTIONS:");
        Console.ResetColor();

        List<NetworkConnection> connections = NetworkUtilities.GetAllConnections();
        int index = 0;
        bool foundIncoming = false;

        while (index < connections.Count)
        {
            NetworkConnection connection = connections[index];

            if (connection.State == TcpState.Established && IsRealIncomingConnection(connection, config))
            {
                foundIncoming = true;
                alertPlayer.Play(AlertType.Warning);

                string processName = NetworkUtilities.GetProcessName(connection.ProcessId);

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  Established incoming connection:");
                Console.WriteLine("    Local: " + connection.LocalEndPoint);
                Console.WriteLine("    Remote: " + connection.RemoteEndPoint);
                Console.WriteLine("    Process: " + processName);
                Console.ResetColor();
            }

            index++;
            if (token.IsCancellationRequested)
            {
                index += connections.Count;
            }
        }

        if (!foundIncoming)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  No established incoming connections found.");
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    private bool IsRealIncomingConnection(NetworkConnection connection, SecurityConfig config)
    {
        bool result = false;

        if (connection.State == TcpState.Listen)
        {
            result = true;
        }
        else if (connection.State == TcpState.Established)
        {
            string processName = NetworkUtilities.GetProcessName(connection.ProcessId);

            bool isWhitelisted = config.WhitelistedProcesses.Any(
                p => string.Equals(p, processName, StringComparison.OrdinalIgnoreCase)
            );
            bool isKnownSuspicious = config.KnownSuspiciousProcesses.ContainsKey(processName);
            bool sameMachine = IsSameLocalMachine(connection.LocalEndPoint, connection.RemoteEndPoint);

            if (!sameMachine)
            {
                if ((isWhitelisted || isKnownSuspicious) && connection.LocalEndPoint.Port <= 49151)
                {
                    result = true;
                }
                else
                {
                    if (connection.LocalEndPoint.Port <= 1024 && connection.RemoteEndPoint.Port > 49152)
                    {
                        result = true;
                    }
                }
            }
        }

        return result;
    }

    private bool IsSameLocalMachine(IPEndPoint local, IPEndPoint remote)
    {
        bool result = false;

        if (local != null && remote != null)
        {
            if (IPAddress.IsLoopback(local.Address) && IPAddress.IsLoopback(remote.Address))
            {
                result = true;
            }
            else if (local.Address.Equals(remote.Address))
            {
                result = true;
            }
            else
            {
                IPAddress[] localAddresses = Dns.GetHostAddresses(Dns.GetHostName());
                bool localIsMine = localAddresses.Any(a => a.Equals(local.Address));
                bool remoteIsMine = localAddresses.Any(a => a.Equals(remote.Address));
                result = localIsMine && remoteIsMine;
            }
        }

        return result;
    }
}
