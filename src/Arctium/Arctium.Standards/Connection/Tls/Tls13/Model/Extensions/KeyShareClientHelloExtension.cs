using System.Collections.Generic;

namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
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
