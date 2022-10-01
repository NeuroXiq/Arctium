namespace Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol
{
    class CertificateRequest : Handshake
    {
        public CertificateRequest()
        {
            base.MsgType = HandshakeType.CertificateRequest;
        }
    }
}
