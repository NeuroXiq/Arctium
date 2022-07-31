namespace Arctium.Connection.Tls.Tls13.Model.Extensions
{
    class KeyShareClientHelloExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.KeyShare;

        public KeyShareEntry[] ClientShares { get; private set; }

        public class KeyShareEntry
        {
            public SupportedGroupExtension.NamedGroup NamedGroup { get; private set; }
            public byte[] KeyExchange { get; private set; }

            public KeyShareEntry(SupportedGroupExtension.NamedGroup namedGroup, byte[] keyExchange)
            {
                NamedGroup = namedGroup;
                KeyExchange = keyExchange;
            }
        }


        public KeyShareClientHelloExtension(KeyShareEntry[] entries)
        {
            ClientShares = entries;
        }
    }
}
