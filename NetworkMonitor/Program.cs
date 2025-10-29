using NetworkMonitor;

Console.Title = "Network Security Monitor";
Console.WriteLine("🚀 Monitor de Seguridad de Red Avanzado");
Console.WriteLine("=========================================\n");

var monitor = new AdvancedNetworkMonitor();
try
{
    monitor.StartEnhancedMonitoring();
}
catch (Exception ex)
{
    monitor.StopMonitoring();
    Console.WriteLine($"Error crítico: {ex.Message}");
    Console.WriteLine("Asegúrate de ejecutar como Administrador");
}

Console.WriteLine("Presiona cualquier tecla para salir...");
Console.ReadKey();
