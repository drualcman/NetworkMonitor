namespace NetworkMonitor.Core;
internal static class NetworkUtilities
{
    public static List<NetworkConnection> GetAllConnections()
    {
        List<NetworkConnection> connections = new List<NetworkConnection>();
        try
        {
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            TcpConnectionInformation[] tcpConnections = properties.GetActiveTcpConnections();

            int index = 0;
            while (index < tcpConnections.Length)
            {
                TcpConnectionInformation tcp = tcpConnections[index];
                NetworkConnection connection = new NetworkConnection();
                connection.LocalEndPoint = tcp.LocalEndPoint;
                connection.RemoteEndPoint = tcp.RemoteEndPoint;
                connection.State = tcp.State;
                connection.ProcessId = GetProcessIdByPort(tcp.LocalEndPoint.Port);
                connections.Add(connection);
                index++;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error getting connections: " + ex.Message);
        }

        return connections;
    }

    public static int GetProcessIdByPort(int port)
    {
        int result = -1;

        try
        {
            Process process = new Process();
            process.StartInfo = new ProcessStartInfo();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c netstat -ano | findstr \":" + port + " \" | findstr \"LISTENING\"";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.CreateNoWindow = true;
            process.Start();

            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            if (!string.IsNullOrWhiteSpace(output))
            {
                string[] lines = output.Split('\n');
                int lineIndex = 0;
                while (lineIndex < lines.Length)
                {
                    string line = lines[lineIndex];
                    if (line.Contains("LISTENING"))
                    {
                        string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 5)
                        {
                            int pid;
                            if (int.TryParse(parts[parts.Length - 1], out pid))
                            {
                                result = pid;
                            }
                        }
                    }
                    lineIndex++;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error getting PID for port " + port + ": " + ex.Message);
        }

        return result;
    }

    public static string GetProcessName(int processId)
    {
        string name = "Unknown";
        if (processId > 0)
        {
            try
            {
                Process process = Process.GetProcessById(processId);
                name = process.ProcessName;
            }
            catch
            {
                name = "Unknown";
            }
        }
        return name;
    }
}
