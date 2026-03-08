using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public interface IDnsServerMessageIOAdapter
    {
        void Configure(Func<Message, Task<Message>> serverProcessMessage, CancellationToken serverStopCancellationToken);
        void OnServerStart();
        void OnServerStop();
    }
}
