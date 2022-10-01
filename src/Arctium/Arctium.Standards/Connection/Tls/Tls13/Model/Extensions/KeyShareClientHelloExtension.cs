namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
{
    class KeyShareClientHelloExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.KeyShare;

        public KeyShareEntry[] ClientShares { get; private set; }

        public KeyShareClientHelloExtension(KeyShareEntry[] entries)
        {
            ClientShares = entries;
        }
    }
}
