namespace NetworkMonitor.Analyzers;

internal class ListeningServicesChecker : IAnalyzer
{
    private readonly AlertSoundPlayer alertPlayer = new AlertSoundPlayer();

    public void Analyze(SecurityConfig config, CancellationToken token)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("LISTENING SERVICES:");
        Console.ResetColor();

        IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
        IPEndPoint[] listeners = properties.GetActiveTcpListeners();
        bool foundSuspicious = false;
        int index = 0;

        while (index < listeners.Length)
        {
            IPEndPoint listener = listeners[index];
            int pid = NetworkUtilities.GetProcessIdByPort(listener.Port);
            string processName = NetworkUtilities.GetProcessName(pid);

            bool suspicious = IsSuspicious(listener, processName, config);

            if (suspicious)
            {
                foundSuspicious = true;
                alertPlayer.Play(AlertType.Critical);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("   Suspicious port: " + listener.Port + " - Process: " + processName);
                Console.ResetColor();
            }
            else
            {
                if (processName != "System" && processName != "svchost" && processName != "Desconocido")
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("   Port: " + listener.Port + " - Process: " + processName);
                    Console.ResetColor();
                }
            }

            index++;
            if (token.IsCancellationRequested)
            {
                index += listeners.Length;
            }
        }

        if (!foundSuspicious)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("   No suspicious listening services found.");
            Console.ResetColor();
        }

        Console.WriteLine();
    }

    private bool IsSuspicious(IPEndPoint listener, string processName, SecurityConfig config)
    {
        bool result = true;

        if (processName == "System" || processName == "svchost")
        {
            result = false;
        }
        else if (config.WhitelistedPorts.Contains(listener.Port))
        {
            result = false;
        }
        else if (config.WhitelistedProcesses.Contains(processName.ToLower()))
        {
            result = false;
        }
        else if (listener.Address.ToString() == "127.0.0.1" || listener.Address.ToString() == "::1")
        {
            result = false;
        }

        return result;
    }
}