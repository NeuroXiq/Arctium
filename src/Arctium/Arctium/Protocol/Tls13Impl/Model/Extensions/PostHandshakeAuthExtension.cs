using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    internal class PostHandshakeAuthExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.PostHandshakeAuth;
    }
}
