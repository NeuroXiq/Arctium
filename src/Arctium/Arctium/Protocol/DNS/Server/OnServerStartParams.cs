using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public class OnServerStartParams
    {
        public DnsServerNextDelegate Next { get; private set; }

        public CancellationToken ServerStopCancellationToken { get; private set; }

        public OnServerStartParams(
            DnsServerNextDelegate next,
            CancellationToken serverStopCancellationToken)
        {
            Next = next;
            ServerStopCancellationToken = serverStopCancellationToken;
        }
    }
}
