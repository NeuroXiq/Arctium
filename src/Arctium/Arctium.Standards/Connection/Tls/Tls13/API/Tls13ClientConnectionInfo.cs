using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Standards.Connection.Tls.Tls13.Protocol;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ClientConnectionInfo
    {
        /// <summary>
        /// Connected using session resumption using tickets mechanism (not using PSK)
        /// </summary>
        public bool IsPskSessionResumption { get; private set; }

        /// <summary>
        /// Certificates that server sends (first cert must be server certificate, next one in any order are x509 cert path)
        /// </summary>
        public byte[][] ServerCertificates { get; private set; }

        /// <summary>
        /// Named groups used to exchange keys, null if session was resumed
        /// </summary>
        public NamedGroup? KeyExchangeNamedGroup { get; private set; }

        /// <summary>
        /// Sginature scheme that server negotiated and was verified
        /// </summary>
        public SignatureScheme? ServerCertificateVerifySignatureScheme { get; private set; }

        /// <summary>
        /// Cryptographic algorithm that is used under connection
        /// </summary>
        public CipherSuite CipherSuite { get; private set; }

        /// <summary>
        /// True if server requested certificate from client in Handshake process 
        /// othewise false
        /// </summary>
        public bool ServerRequestedCertificateInHandshake { get; private set; }

        /// <summary>
        /// If Record Size Limit extension was negotiated successfully then
        /// value indicated record layer max plaintext length.
        /// If extension was not negotiated then value is null
        /// </summary>
        public ushort? ExtensionRecordSizeLimit { get; private set; }

        /// <summary>
        /// Result of select ALPN (application layer protocol negotiation) by server.
        /// If server did not sent extension value is null.
        /// If server sent extension inner value of object
        /// always stores not null and not empty single protocol name selected by server
        /// </summary>
        public ExtensionResultALPN ExtensionResultALPN { get; private set; }

        /// <summary>
        /// internal constructor to create API connection info from protocol result
        /// </summary>
        /// <param name="info"></param>
        internal Tls13ClientConnectionInfo(Tls13ClientProtocol.ConnectedInfo info)
        {
            IsPskSessionResumption = info.IsPskSessionResumption;
            ServerCertificates = info.ServerCertificates;
            KeyExchangeNamedGroup = info.KeyExchangeNamedGroup != null ? (NamedGroup?)info.KeyExchangeNamedGroup.Value : null;
            ServerCertificateVerifySignatureScheme = info.ServerCertificateVerifySignatureScheme.HasValue ?
                (SignatureScheme?)info.ServerCertificateVerifySignatureScheme :
                null;

            CipherSuite = (API.CipherSuite)info.CipherSuite;
            ExtensionRecordSizeLimit = info.NegotiatedRecordSizeLimitExtension;

            if (info.ExtensionResultALPN != null)
                ExtensionResultALPN = new ExtensionResultALPN(info.ExtensionResultALPN);
        }
    }
}
