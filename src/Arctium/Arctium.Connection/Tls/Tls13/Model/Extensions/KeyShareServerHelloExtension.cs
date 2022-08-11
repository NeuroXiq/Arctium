namespace Arctium.Connection.Tls.Tls13.Model.Extensions
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
