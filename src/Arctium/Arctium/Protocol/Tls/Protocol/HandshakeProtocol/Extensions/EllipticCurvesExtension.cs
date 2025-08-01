namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions
{
    class EllipticCurvesExtension : HandshakeExtension
    {
        public NamedCurve[] EllipticCurveList;

        public EllipticCurvesExtension() : base(HandshakeExtensionType.EllipticCurves)
        {
        }
    }
}
