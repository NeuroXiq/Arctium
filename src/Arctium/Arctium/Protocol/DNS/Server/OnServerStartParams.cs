using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public class OnServerStartParams
    {
        public Func<Message, Task<Message>> ProcessMessageAsync { get; private set; }
        public CancellationToken ServerStopCancellationToken { get; private set; }

        public OnServerStartParams(
            Func<Message, Task<Message>> onMessageReceived,
            CancellationToken serverStopCancellationToken)
        {
            ProcessMessageAsync = onMessageReceived;
            ServerStopCancellationToken = serverStopCancellationToken;
        }
    }
}
