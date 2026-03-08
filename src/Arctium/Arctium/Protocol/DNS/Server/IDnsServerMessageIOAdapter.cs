using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public interface IDnsServerMessageIOAdapter
    {
        void Configure(Func<Message, Task<Message>> onMessageReceived);
        void OnServerStart();
        void OnServerStop();
    }
}
