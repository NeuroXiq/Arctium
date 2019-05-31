namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    class ECPointFormatsExtension : HandshakeExtension
    {
        public ECPointFormat[] EcPointFormatList;

        public ECPointFormatsExtension(HandshakeExtensionType type) : base(HandshakeExtensionType.EcPointFormats)
        {

        }
    }
}
