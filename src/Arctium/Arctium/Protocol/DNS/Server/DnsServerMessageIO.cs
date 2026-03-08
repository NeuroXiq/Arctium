using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerMessageIO : IDnsServerMessageIO
    {
        private List<IDnsServerMessageIOAdapter> adapters;
        private Func<Message, Task<Message>> onMessageReceived;

        public DnsServerMessageIO()
        {
            adapters = new List<IDnsServerMessageIOAdapter>();
        }

        public void Configure(Func<Message, Task<Message>> onMessageReceived)
        {
            this.onMessageReceived = onMessageReceived;

            foreach (var adapter in adapters)
            {
                adapter.Configure(OnClientMessageReceived);
            }
        }

        public void AddAdapter(IDnsServerMessageIOAdapter adapter)
        {
            adapters.Add(adapter);
        }

        public void OnServerStart()
        {
            foreach (var adapter in adapters)
            {
                adapter.OnServerStart();
            }
        }

        public void OnServerStop()
        {
            foreach (var adapter in adapters)
            {
                adapter.OnServerStop();
            }
        }

        private Task<Message> OnClientMessageReceived(Message clientMessage)
        {
            return onMessageReceived(clientMessage);
        }
    }
}
