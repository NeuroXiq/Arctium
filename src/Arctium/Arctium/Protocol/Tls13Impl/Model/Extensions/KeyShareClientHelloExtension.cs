using System.Collections.Generic;
using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    class KeyShareClientHelloExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.KeyShare;

        public List<KeyShareEntry> ClientShares { get; private set; }

        public KeyShareClientHelloExtension(KeyShareEntry[] entries)
        {
            ClientShares = new List<KeyShareEntry>(entries);
        }
    }
}
