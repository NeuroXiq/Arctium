using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
{
    internal class PostHandshakeAuthExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.PostHandshakeAuth;
    }
}
