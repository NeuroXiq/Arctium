using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Protocol.HandshakeProtocol
{
    class CertificateRequest : Handshake
    {
        public CertificateRequest()
        {
            base.MsgType = HandshakeType.CertificateRequest;
        }
    }
}
