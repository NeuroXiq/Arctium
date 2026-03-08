using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public interface IDnsServerMessageIO
    {
        void AddAdapter(IDnsServerMessageIOAdapter adapter);
        void Configure(Func<Message, Task<Message>> onMessageReceived);
        void OnServerStart();
        void OnServerStop();
    }
}
