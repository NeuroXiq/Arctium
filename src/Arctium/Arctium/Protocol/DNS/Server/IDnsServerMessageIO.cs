using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public interface IDnsServerMessageIO
    {
        void AddAdapter(IDnsServerMessageIOAdapter adapter);
        void OnServerStart(OnServerStartParams onServerStartParams);
        void OnServerStop();
    }
}
