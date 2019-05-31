namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    class EllipticCurveExtension : HandshakeExtension
    {
        public NamedCurve[] EllipticCurveList;

        public EllipticCurveExtension(HandshakeExtensionType type) : base(HandshakeExtensionType.EllipticCurves)
        {
        }
    }
}
