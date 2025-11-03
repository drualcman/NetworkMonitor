namespace NetworkMonitor.Core;
internal class AlertSoundPlayer
{
    public void Play(AlertType type)
    {
        try
        {
            if (type == AlertType.Critical)
            {
                Console.Beep(800, 800);
                Thread.Sleep(50);
                Console.Beep(800, 800);
            }
            else if (type == AlertType.Warning)
            {
                Console.Beep(1000, 500);
            }
            else if (type == AlertType.Info)
            {
                Console.Beep(1200, 300);
            }
            else
            {
                Console.Beep(1000, 500);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Sound alert unavailable: " + ex.Message);
        }
    }
}
