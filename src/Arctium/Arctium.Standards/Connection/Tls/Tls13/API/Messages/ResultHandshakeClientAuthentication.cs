using Arctium.Standards.X509.X509Cert;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Messages
{
    /// <summary>
    /// Represents resut of client authentication during TLS handshake process
    /// </summary>
    public class ResultHandshakeClientAuthentication
    {
        /// <summary>
        /// Represents certificate that was sent by client during client authentication in handshake.
        /// This value can be empty array if client sent empty certificate
        /// </summary>
        public byte[] ClientCertificate { get; private set; }

        /// <summary>
        /// Represents parent client certificates that was sent by client during client authentication in handshake.
        /// This value can be empty array if client did not sent any parent certificates
        /// </summary>
        public byte[][] ClientParentCertificates { get; private set; }

        public ResultHandshakeClientAuthentication(byte[] clientCertificate, byte[][] clientParentCertificates)
        {
            ClientCertificate = clientCertificate;
            ClientParentCertificates = clientParentCertificates;
        }
    }
}
