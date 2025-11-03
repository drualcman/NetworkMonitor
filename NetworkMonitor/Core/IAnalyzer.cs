namespace NetworkMonitor.Core;
internal interface IAnalyzer
{
    void Analyze(SecurityConfig config, CancellationToken token);
}
