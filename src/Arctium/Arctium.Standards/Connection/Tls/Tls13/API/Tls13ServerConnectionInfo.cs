using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Standards.Connection.Tls.Tls13.API.Messages;
using System.Linq;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ServerConnectionInfo
    {
        public ExtensionResultALPN ExtensionResultALPN { get; private set; }
        
        /// <summary>
        /// If Server extension was configured stores action taken by server by current cofiguration for this extension.
        /// If extesnion was not configures value is null
        /// </summary>
        public ExtensionServerConfigServerName.ResultAction? ExtensionResultServerName { get; private set; }

        /// <summary>
        /// If this values is not null then server requested client authentication during handshake.
        /// Result is stored in object instance.
        /// If value is null then server did not sent CertificateRequest during handshake (did not requested
        /// client authentication)
        /// </summary>
        public ResultHandshakeClientAuthentication ResultHandshakeClientAuthentication { get; private set; }

        public bool ClientSupportPostHandshakeAuthentication { get; private set; }

        /// <summary>
        /// True if current connection was established using session resumption mechanism
        /// False if performed full handshake
        /// </summary>
        public bool IsPskSessionResumption { get; private set; }

        internal Tls13ServerConnectionInfo(Protocol.Tls13ServerProtocol.ConnectedInfo internalConnInfo)
        {
            if (internalConnInfo.ExtensionResultALPN != null)
                ExtensionResultALPN = new ExtensionResultALPN(internalConnInfo.ExtensionResultALPN);

            ExtensionResultServerName = internalConnInfo.ExtensionResultServerName;

            ClientSupportPostHandshakeAuthentication = internalConnInfo.ClientSupportPostHandshakeAuthentication;
            IsPskSessionResumption = internalConnInfo.IsPskSessionResumption;

            if (internalConnInfo.ClientHandshakeAuthenticationCertificatesSentByClient != null)
            {
                var certs = internalConnInfo.ClientHandshakeAuthenticationCertificatesSentByClient;
                var clientCert = certs.Length > 0 ? certs[0] : new byte[0];
                var parentCerts = certs.Length > 1 ? certs.Select(c => (byte[])c.Clone()).ToArray() : new byte[0][];
                ResultHandshakeClientAuthentication = new ResultHandshakeClientAuthentication(clientCert, parentCerts);
            }
        }
    }
}
