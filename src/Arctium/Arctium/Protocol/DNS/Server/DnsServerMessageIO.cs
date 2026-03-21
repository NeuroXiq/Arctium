using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerMessageIO : IDnsServerMessageIO
    {
        private List<IDnsServerMessageIOAdapter> adapters;
        private OnServerStartParams onServerStartParams;
        DnsServerNextDelegate nextWrapper;

        public DnsServerMessageIO()
        {
            adapters = new List<IDnsServerMessageIOAdapter>();
            nextWrapper = new DnsServerNextDelegate(Next);
        }

        public void AddAdapter(IDnsServerMessageIOAdapter adapter)
        {
            adapters.Add(adapter);
        }

        public void OnServerStart(OnServerStartParams onServerStartParams)
        {
            this.onServerStartParams = onServerStartParams;
            var ioParams = new OnServerStartParams(nextWrapper, onServerStartParams.ServerStopCancellationToken);

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

        public Task Next(DnsRequestContext context)
        {
            return onServerStartParams.Next.Next(context);
        }
    }
}
