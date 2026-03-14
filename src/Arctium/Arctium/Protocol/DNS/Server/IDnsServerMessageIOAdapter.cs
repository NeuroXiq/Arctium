using Arctium.Protocol.DNS.Model;

namespace Arctium.Protocol.DNS.Server
{
    public interface IDnsServerMessageIOAdapter
    {
        void OnServerStart(OnServerStartParams onServerStartParams);
        void OnServerStop();
    }
}
