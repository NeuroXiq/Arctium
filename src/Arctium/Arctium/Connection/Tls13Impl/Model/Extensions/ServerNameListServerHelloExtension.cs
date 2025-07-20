using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
{
    internal class ServerNameListServerHelloExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.ServerName;
    }
}
