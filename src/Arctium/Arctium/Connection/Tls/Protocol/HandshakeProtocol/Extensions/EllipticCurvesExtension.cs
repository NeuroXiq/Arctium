namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    class EllipticCurvesExtension : HandshakeExtension
    {
        public NamedCurve[] EllipticCurveList;

        public EllipticCurvesExtension(HandshakeExtensionType type) : base(HandshakeExtensionType.EllipticCurves)
        {
        }
    }
}
