using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

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
