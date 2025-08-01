using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    internal class ServerNameListServerHelloExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.ServerName;
    }
}
