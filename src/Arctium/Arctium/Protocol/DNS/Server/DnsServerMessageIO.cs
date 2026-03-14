using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerMessageIO : IDnsServerMessageIO
    {
        private List<IDnsServerMessageIOAdapter> adapters;
        private Func<Message, Task<Message>> onMessageReceived;
        private CancellationToken serverStopCancellationToken;
        private OnServerStartParams onServerStartParams;

        public DnsServerMessageIO()
        {
            adapters = new List<IDnsServerMessageIOAdapter>();
        }

        public void AddAdapter(IDnsServerMessageIOAdapter adapter)
        {
            adapters.Add(adapter);
        }

        public void OnServerStart(OnServerStartParams onServerStartParams)
        {
            this.onServerStartParams = onServerStartParams;

            foreach (var adapter in adapters)
            {
                adapter.OnServerStart(onServerStartParams);
            }
        }

        public void OnServerStop()
        {
            foreach (var adapter in adapters)
            {
                adapter.OnServerStop();
            }
        }
    }
}
