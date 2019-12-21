namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol
{
    class CertificateVerify : Handshake
    {
        public CertificateVerify()
        {
            base.MsgType = HandshakeType.CertificateVerify;
        }
    }
}
