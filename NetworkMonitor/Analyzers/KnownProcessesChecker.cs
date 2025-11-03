namespace NetworkMonitor.Analyzers;
internal class KnownProcessesChecker : IAnalyzer
{
    public void Analyze(SecurityConfig config, CancellationToken token)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("KNOWN PROCESSES WITH INCOMING CONNECTIONS:");
        Console.ResetColor();

        List<NetworkConnection> connections = NetworkUtilities.GetAllConnections();
        Dictionary<int, string> incomingProcesses = new Dictionary<int, string>();
        bool foundProcesses = false;

        int index = 0;
        while (index < connections.Count)
        {
            NetworkConnection connection = connections[index];
            if (connection.State == TcpState.Established)
            {
                string processName = NetworkUtilities.GetProcessName(connection.ProcessId);
                if (config.KnownSuspiciousProcesses.ContainsKey(processName))
                {
                    if (!incomingProcesses.ContainsKey(connection.ProcessId))
                    {
                        incomingProcesses.Add(connection.ProcessId, processName);
                    }
                }
            }
            index++;
            if (token.IsCancellationRequested)
            {
                index += connections.Count;
            }
        }

        List<int> keys = incomingProcesses.Keys.ToList();
        int processIndex = 0;
        while (processIndex < keys.Count)
        {
            int pid = keys[processIndex];
            string name = incomingProcesses[pid];
            foundProcesses = true;

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  " + name + " (PID: " + pid + ")");
            Console.WriteLine("    " + config.KnownSuspiciousProcesses[name]);

            bool hasExternal = HasExternalConnection(pid);
            if (hasExternal)
            {
                Console.WriteLine("    External incoming connections detected.");
            }
            else
            {
                Console.WriteLine("    Only local connections detected (check manually).");
            }

            Console.ResetColor();
            processIndex++;
        }

        if (!foundProcesses)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  No known suspicious processes with active connections.");
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    private bool HasExternalConnection(int processId)
    {
        bool result = false;
        List<NetworkConnection> connections = NetworkUtilities.GetAllConnections();
        int index = 0;

        while (index < connections.Count)
        {
            NetworkConnection connection = connections[index];
            if (connection.ProcessId == processId && connection.State == TcpState.Established)
            {
                if (!IsSameLocalMachine(connection.LocalEndPoint, connection.RemoteEndPoint))
                {
                    result = true;
                }
            }
            index++;
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
