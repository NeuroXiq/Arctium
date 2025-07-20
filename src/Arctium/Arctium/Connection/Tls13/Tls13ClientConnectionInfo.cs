using Arctium.Standards.Connection.Tls13.Extensions;
using Arctium.Standards.Connection.Tls13.Messages;
using Arctium.Standards.Connection.Tls13Impl.Protocol;
using System.Linq;

namespace Arctium.Standards.Connection.Tls13
{
    /// <summary>
    /// Represents current connection state on client side.
    /// </summary>
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
        /// Result of 'Server Name' extension RFC 6066.
        /// When true then server send a 'Server name' extension to client.
        /// When false 'Server Name' extension was not received from server
        /// </summary>
        public bool ExtensionResultServerName { get; private set; }

        /// <summary>
        /// Represents result of client authentication during handshake.
        /// When this value is not null then server requested client authentication during handshake.
        /// Object represent result of this authentication.
        /// If value is null then server did not requested client authenticaion durign handshake.
        /// </summary>
        public ResultHandshakeClientAuthentication ResultHandshakeClientAuthentication { get; private set; }

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

            CipherSuite = (CipherSuite)info.CipherSuite;
            ExtensionRecordSizeLimit = info.NegotiatedRecordSizeLimitExtension;

            if (info.ExtensionResultALPN != null)
                ExtensionResultALPN = new ExtensionResultALPN(info.ExtensionResultALPN);

            ExtensionResultServerName = info.ExtensionResultServerName;

            if (info.ClientHandshakeAuthenticationCertificatesSentByClient != null)
            {
                var certs = info.ClientHandshakeAuthenticationCertificatesSentByClient;
                byte[] clientCert = certs.Length > 0 ? (byte[])certs[0].Clone() : new byte[0];
                byte[][] parentCerts = certs.Length > 1 ? certs.Skip(1).Select(c => (byte[])c.Clone()).ToArray() : new byte[0][];

                ResultHandshakeClientAuthentication = new ResultHandshakeClientAuthentication(clientCert, parentCerts);
            }
        }
    }
}
