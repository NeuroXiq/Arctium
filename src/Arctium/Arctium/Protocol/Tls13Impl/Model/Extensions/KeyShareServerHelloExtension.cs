using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    internal class KeyShareServerHelloExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.KeyShare;

        public KeyShareEntry ServerShare { get; private set; }

        public KeyShareServerHelloExtension(KeyShareEntry entry)
        {
            ServerShare = entry;
        }
    }
}
