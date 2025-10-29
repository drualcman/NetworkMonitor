using System.Text.Json;

namespace NetworkMonitor
{
    public class AdvancedNetworkMonitor
    {
        private SecurityConfig config;
        private bool isMonitoring;

        public AdvancedNetworkMonitor()
        {
            LoadConfiguration();
        }

        private void LoadConfiguration()
        {
            try
            {
                if (File.Exists("security_config.json"))
                {
                    var json = File.ReadAllText("security_config.json");
                    config = JsonSerializer.Deserialize<SecurityConfig>(json);
                }
                else
                {
                    CreateDefaultConfig();
                }
            }
            catch
            {
                CreateDefaultConfig();
            }
        }

        private void CreateDefaultConfig()
        {
            config = new SecurityConfig
            {
                WhitelistedPorts = [
                    // Puertos estándar
                    80, 443, 53, 21, 22, 25, 110, 143, 
                    // Tus puertos específicos
                    5432, 7680, 4767, 53241, 63342, 42050,
                    // Puertos Windows
                    135, 139, 445, 5040,
                    // Puertos servicios Windows  
                    49664, 49665, 49666, 49667, 49668, 49669, 49672,
                    // Puertos efímeros del sistema que aparecen
                    44321, 44350, 44380, 44399, 59717, 59719, 61989, 61994
                ],
                WhitelistedProcesses = [
                    "chrome", "firefox", "edge", "explorer", "svchost",
                    "winlogon", "services", "system", "postgres", "java",
                    "code", "devenv", "msedge", "notepad", "taskmgr",
                    "wininit", "csrss", "lsass", "smss", "spoolsv",
                    "docker", "node", "python", "php",
                    "pangps", "embeddings-server", "datagrip64",
                    "com.docker.backend", "onedrive.sync.service",
                    "jhi_service", "slack"
                // NOTA: "powershell" NO está en la whitelist - eso está BIEN
                ],
                CheckInterval = 5000,
                LogToFile = true
            };

            SaveConfiguration();
        }

        public void StartEnhancedMonitoring()
        {
            Console.WriteLine("🚀 Iniciando Monitoreo Mejorado de Seguridad");
            Console.WriteLine("=============================================\n");
            isMonitoring = true;

            // Hilo separado para detectar la tecla Q
            var keyThread = new Thread(() =>
            {
                while (isMonitoring)
                {
                    if (Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Q)
                        {
                            StopMonitoring();
                            break;
                        }
                    }
                    Thread.Sleep(100);
                }
            });
            keyThread.Start();

            while (isMonitoring)
            {
                Console.Clear();
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Escaneando... (Presiona Q para salir)\n");

                CheckListeningServices();
                CheckEstablishedIncoming();
                CheckSuspiciousProcesses();
                CheckSuspiciousKnownProcesses();

                Thread.Sleep(config.CheckInterval);
            }

            keyThread.Join();
        }

        private void CheckListeningServices()
        {
            try
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("🔍 SERVICIOS ESCUCHANDO:");
                Console.ResetColor();

                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpListeners = properties.GetActiveTcpListeners();
                bool foundSuspicious = false;

                foreach (var listener in tcpListeners)
                {
                    int pid = GetProcessIdByPort(listener.Port);
                    string processName = pid > 0 ? GetProcessName(pid) : "Desconocido";

                    // VERIFICACIÓN MEJORADA - Solo alertar si es REALMENTE sospechoso
                    if (IsReallySuspicious(listener.Port, processName, listener.Address))
                    {
                        foundSuspicious = true;

                        // 🔈 REPRODUCIR SONIDO DE ALERTA
                        PlayAlertSound(AlertType.Warning);

                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"   ⚠️  PUERTO SOSPECHOSO: {listener.Port}");
                        Console.WriteLine($"      Proceso: {processName} (PID: {pid})");
                        Console.WriteLine($"      Dirección: {listener.Address}");
                        Console.ResetColor();

                        LogSuspiciousActivity($"Servicio escuchando en puerto no autorizado: {listener.Port} - Proceso: {processName}");
                    }
                    else
                    {
                        // Solo mostrar los que NO son sospechosos si es un proceso conocido
                        if (processName != "System" && processName != "svchost" && processName != "Desconocido")
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"   ✅ Puerto: {listener.Port} - Proceso: {processName}");
                            Console.ResetColor();
                        }
                    }
                }

                if (!foundSuspicious)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("   ✅ No se encontraron servicios sospechosos");
                    Console.ResetColor();
                }
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error en CheckListeningServices: {ex.Message}");
            }
        }


        // NUEVO MÉTODO - Lógica mejorada para detectar amenazas reales
        private bool IsReallySuspicious(int port, string processName, IPAddress address)
        {
            // NO es sospechoso si:

            // 1. Es un proceso del sistema Windows
            if (processName == "System" || processName == "svchost")
                return false;

            // 2. Es un puerto de servicio Windows
            if (IsWindowsServicePort(port))
                return false;

            // 3. Está en la whitelist de puertos
            if (config.WhitelistedPorts.Contains(port))
                return false;

            // 4. Es un proceso whitelisted
            if (IsProcessWhitelisted(processName))
                return false;

            // 5. Está escuchando solo localmente
            if (address.ToString() == "127.0.0.1" || address.ToString() == "::1")
                return false;

            // 6. El proceso es "Desconocido" - esto SÍ es sospechoso
            if (processName == "Desconocido")
                return true;

            // 7. Si es PowerShell en puertos altos - probablemente del ThreatSimulator
            if (processName.ToLower() == "powershell" && port > 1000)
                return true; // Esto SÍ es sospechoso

            // 8. Cualquier otro caso es sospechoso
            return true;
        }

        private void CheckEstablishedIncoming()
        {
            try
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("🌐 CONEXIONES ESTABLECIDAS ENTRANTES:");
                Console.ResetColor();

                var connections = GetAllNetworkConnections();
                bool foundIncoming = false;

                foreach (var connection in connections)
                {
                    if (connection.State == TcpState.Established && IsRealIncomingConnection(connection))
                    {
                        foundIncoming = true;

                        // 🔈 REPRODUCIR SONIDO DE ALERTA
                        PlayAlertSound(AlertType.Critical);

                        string processName = GetProcessName(connection.ProcessId);

                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"   🔄 Conexión entrante establecida:");
                        Console.WriteLine($"      Local: {connection.LocalEndPoint}");
                        Console.WriteLine($"      Remoto: {connection.RemoteEndPoint}");
                        Console.WriteLine($"      Proceso: {processName}");
                        Console.ResetColor();
                    }
                }

                if (!foundIncoming)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("   ✅ No hay conexiones entrantes establecidas");
                    Console.ResetColor();
                }
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error en CheckEstablishedIncoming: {ex.Message}");
            }
        }
        private void CheckSuspiciousProcesses()
        {
            try
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("📊 PROCESOS CON CONEXIONES DE RED:");
                Console.ResetColor();

                var processes = new Dictionary<int, string>();
                var connections = GetAllNetworkConnections();

                // Recolectar procesos únicos
                foreach (var conn in connections)
                {
                    if (conn.ProcessId > 0 && !processes.ContainsKey(conn.ProcessId))
                    {
                        processes[conn.ProcessId] = GetProcessName(conn.ProcessId);
                    }
                }

                foreach (var process in processes)
                {
                    if (!IsProcessWhitelisted(process.Value))
                    {
                        // 🔈 REPRODUCIR SONIDO DE ALERTA
                        PlayAlertSound(AlertType.Info);

                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"   ⚠️  Proceso no whitelisted: {process.Value} (PID: {process.Key})");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"   ✅ Proceso: {process.Value} (PID: {process.Key})");
                        Console.ResetColor();
                    }
                }
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error en CheckSuspiciousProcesses: {ex.Message}");
            }
        }


        private bool IsRealIncomingConnection(NetworkConnection connection)
        {
            // Conexión LISTENING siempre es entrante
            if (connection.State == TcpState.Listen)
                return true;

            // Para conexiones ESTABLISHED, es entrante si:
            // - Puerto local es bajo (< 1024) Y puerto remoto es alto (> 49152)
            // - O si el proceso está en nuestra lista de servicios conocidos
            if (connection.State == TcpState.Established)
            {
                var knownServices = new List<string> { "PanGPS", "embeddings-server", "datagrip64" };
                string processName = GetProcessName(connection.ProcessId);

                // Si es un servicio conocido escuchando, es entrante
                if (knownServices.Contains(processName) && connection.LocalEndPoint.Port <= 49151)
                    return true;

                // Lógica original mejorada
                return connection.LocalEndPoint.Port <= 1024 &&
                       connection.RemoteEndPoint.Port > 49152;
            }

            return false;
        }

        private bool IsWindowsServicePort(int port)
        {
            var windowsPorts = new List<int> {
                // Puertos bien conocidos de Windows
                135, 139, 445, 5040,
                // Rango de puertos efímeros de Windows
                44321, 44350, 44380, 44399, 59717, 59719, 61989, 61994,
                // Puertos de servicios Windows
                49664, 49665, 49666, 49667, 49668, 49669, 49670, 49671, 49672
            };
            return windowsPorts.Contains(port);
        }

        // Métodos existentes que ya tenías (GetAllNetworkConnections, GetProcessIdByPort, etc.)
        private List<NetworkConnection> GetAllNetworkConnections()
        {
            var connections = new List<NetworkConnection>();

            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpConnections();

                foreach (var tcpConnection in tcpConnections)
                {
                    var connection = new NetworkConnection
                    {
                        LocalEndPoint = tcpConnection.LocalEndPoint,
                        RemoteEndPoint = tcpConnection.RemoteEndPoint,
                        State = tcpConnection.State,
                        ProcessId = GetProcessIdByPort(tcpConnection.LocalEndPoint.Port)
                    };

                    connections.Add(connection);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error obteniendo conexiones: {ex.Message}");
            }

            return connections;
        }
        private int GetProcessIdByPort(int port)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c netstat -ano | findstr \":{port} \" | findstr \"LISTENING\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (!string.IsNullOrEmpty(output))
                {
                    var lines = output.Split('\n');
                    foreach (var line in lines)
                    {
                        if (line.Contains("LISTENING"))
                        {
                            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 5)
                            {
                                // El PID es el último elemento
                                if (int.TryParse(parts[parts.Length - 1], out int pid))
                                {
                                    return pid;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error obteniendo PID para puerto {port}: {ex.Message}");
            }
            return -1;
        }

        private string GetProcessName(int processId)
        {
            if (processId <= 0)
                return "Desconocido";

            try
            {
                var process = Process.GetProcessById(processId);
                return process.ProcessName;
            }
            catch
            {
                return "Desconocido";
            }
        }

        private bool IsProcessWhitelisted(string processName)
        {
            return config.WhitelistedProcesses.Contains(processName.ToLower());
        }

        private void LogSuspiciousActivity(string message)
        {
            if (config.LogToFile)
            {
                try
                {
                    var logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {message}\n";
                    File.AppendAllText("network_security.log", logEntry);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error escribiendo log: {ex.Message}");
                }
            }
        }

        private void SaveConfiguration()
        {
            var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText("security_config.json", json);
        }

        public void StopMonitoring()
        {
            isMonitoring = false;
            Console.WriteLine("\n🛑 Monitoreo detenido.");
        }
        private void CheckSuspiciousKnownProcesses()
        {
            var suspiciousButKnown = new Dictionary<string, string>
    {
        { "PanGPS", "GlobalProtect VPN - Software corporativo" },
        { "embeddings-server", "Servicio de IA - Legítimo" },
        { "datagrip64", "JetBrains DataGrip - IDE legítimo" },
        { "com.docker.backend", "Docker Desktop - Legítimo" },
        { "OneDrive.Sync.Service", "Microsoft OneDrive - Legítimo" },
        { "jhi_service", "Servicio Intel - Legítimo" }
    };

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("📋 PROCESOS CONOCIDOS CON CONEXIONES ENTRANTES:");
            Console.ResetColor();

            bool foundProcesses = false;

            // Buscar conexiones establecidas entrantes reales
            var connections = GetAllNetworkConnections();
            var incomingProcesses = new Dictionary<int, string>();

            foreach (var connection in connections)
            {
                // Solo procesos con conexiones entrantes establecidas
                if (connection.State == TcpState.Established && IsRealIncomingConnection(connection))
                {
                    if (connection.ProcessId > 0)
                    {
                        string processName = GetProcessName(connection.ProcessId);
                        if (suspiciousButKnown.ContainsKey(processName))
                        {
                            incomingProcesses[connection.ProcessId] = processName;
                        }
                    }
                }
            }

            // Mostrar solo los que tienen conexiones entrantes
            foreach (var process in incomingProcesses)
            {
                foundProcesses = true;
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"   ⚠️  {process.Value} (PID: {process.Key})");
                Console.WriteLine($"      {suspiciousButKnown[process.Value]}");
                Console.WriteLine($"      Tiene conexiones entrantes establecidas");
                Console.ResetColor();
            }

            if (!foundProcesses)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("   ✅ No hay procesos conocidos con conexiones entrantes");
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        private void PlayAlertSound(AlertType alertType = AlertType.Critical)
        {
            try
            {
                switch (alertType)
                {
                    case AlertType.Critical:
                        Console.Beep(800, 800);   // Sonido grave y largo - para amenazas críticas
                        Thread.Sleep(100);
                        Console.Beep(800, 800);   // Doble beep para mayor alerta
                        break;

                    case AlertType.Warning:
                        Console.Beep(1000, 500);  // Sonido medio - para advertencias
                        break;

                    case AlertType.Info:
                        Console.Beep(1200, 300);  // Sonido agudo y corto - para información
                        break;

                    default:
                        Console.Beep(1000, 500);  // Sonido por defecto
                        break;
                }
            }
            catch (Exception ex)
            {
                // Si Console.Beep falla, mostrar mensaje
                Console.WriteLine($"🔊 ALERTA SONORA NO DISPONIBLE: {ex.Message}");
            }
        }

        public enum AlertType
        {
            Critical,
            Warning,
            Info
        }
    }
}