namespace NetworkMonitor;

internal class AdvancedNetworkMonitor
{
    private readonly List<IAnalyzer> Analyzers;
    private readonly SecurityConfig Config;
    private bool MonitoringActive;
    private CancellationTokenSource CancellationSource;

    public AdvancedNetworkMonitor()
    {
        ConfigManager configManager = new ConfigManager();
        Config = configManager.Load();
        Analyzers = new List<IAnalyzer>
            {
                new ListeningServicesChecker(),
                new EstablishedConnectionsChecker(),
                new SuspiciousProcessesChecker(),
                new KnownProcessesChecker()
            };
        MonitoringActive = false;
        CancellationSource = new CancellationTokenSource();
    }

    public void StartEnhancedMonitoring()
    {
        MonitoringActive = true;
        CancellationSource = new CancellationTokenSource();

        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("🚀 Starting Advanced Network Security Monitor");
        Console.ResetColor();
        Console.WriteLine("=============================================\n");

        Thread inputThread = new Thread(HandleUserInput);
        inputThread.Start();

        while (MonitoringActive && !CancellationSource.Token.IsCancellationRequested)
        {
            Console.Clear();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Scanning... (Press Q to quit)\n");

            int index = 0;
            while (index < Analyzers.Count && !CancellationSource.Token.IsCancellationRequested)
            {
                IAnalyzer analyzer = Analyzers[index];
                analyzer.Analyze(Config, CancellationSource.Token);
                index++;
            }

            if (!CancellationSource.Token.IsCancellationRequested)
            {
                Thread.Sleep(Config.CheckInterval);
            }
        }

        inputThread.Join();

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("\nMonitoring stopped.");
        Console.ResetColor();
    }

    private void HandleUserInput()
    {
        while (MonitoringActive && !CancellationSource.Token.IsCancellationRequested)
        {
            if (Console.KeyAvailable)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Q)
                {
                    StopMonitoring();
                }
            }
            Thread.Sleep(100);
        }
    }

    public void StopMonitoring()
    {
        MonitoringActive = false;
        CancellationSource.Cancel();
    }
}