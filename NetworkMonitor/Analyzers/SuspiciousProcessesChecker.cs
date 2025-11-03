namespace NetworkMonitor.Analyzers;
internal class SuspiciousProcessesChecker : IAnalyzer
{
    private readonly AlertSoundPlayer alertPlayer = new AlertSoundPlayer();

    public void Analyze(SecurityConfig config, CancellationToken token)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("PROCESSES WITH NETWORK CONNECTIONS:");
        Console.ResetColor();

        List<NetworkConnection> connections = NetworkUtilities.GetAllConnections();
        Dictionary<int, string> processes = new Dictionary<int, string>();

        int index = 0;
        while (index < connections.Count)
        {
            NetworkConnection conn = connections[index];
            if (conn.ProcessId > 0 && !processes.ContainsKey(conn.ProcessId))
            {
                string processName = NetworkUtilities.GetProcessName(conn.ProcessId);
                processes.Add(conn.ProcessId, processName);
            }
            index++;
            if (token.IsCancellationRequested)
            {
                index += connections.Count;
            }
        }

        int processIndex = 0;
        List<int> keys = processes.Keys.ToList();
        while (processIndex < keys.Count)
        {
            int pid = keys[processIndex];
            string name = processes[pid];

            if (!IsProcessWhitelisted(name, config))
            {
                alertPlayer.Play(AlertType.Info);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  Non-whitelisted process: " + name + " (PID: " + pid + ")");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  Process: " + name + " (PID: " + pid + ")");
                Console.ResetColor();
            }

            processIndex++;
        }

        Console.WriteLine();
    }

    private bool IsProcessWhitelisted(string processName, SecurityConfig config)
    {
        bool result = false;
        if (!string.IsNullOrWhiteSpace(processName))
        {
            result = config.WhitelistedProcesses.Any(
                p => string.Equals(p, processName, StringComparison.OrdinalIgnoreCase)
            );
        }
        return result;
    }
}

