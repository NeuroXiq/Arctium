namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions
{
    class ECPointFormatsExtension : HandshakeExtension
    {
        public ECPointFormat[] EcPointFormatList;

        public ECPointFormatsExtension(ECPointFormat[] pointFormats) : base(HandshakeExtensionType.EcPointFormats)
        {
            EcPointFormatList = pointFormats;
        }

        public ECPointFormatsExtension(ECPointFormat singlePointFormat) : this(new ECPointFormat[] { singlePointFormat })
        {
            EcPointFormatList = new ECPointFormat[] { singlePointFormat };
        }
    }
}
