using Arctium.Standards.Connection.Tls13.APIModel;
using Arctium.Standards.X509.X509Cert;
using System.Collections.Generic;

namespace Arctium.Standards.Connection.Tls13.Messages
{
    /// <summary>
    /// Configures client authentication client side
    /// </summary>
    public abstract class ClientConfigHandshakeClientAuthentication
    {
        public class Certificates
        {
            public X509CertWithKey ClientCertificate;
            public X509Certificate[] ParentCertificates;
        }


        /// <summary>
        /// Select a certificate path that will be selected to server when authentication requetes.
        /// First certificate must be client certificate
        /// List can be empty then no certificate will be sent
        /// </summary>
        /// <param name="extensionInCertificateRequest">Extensions received from server in extension field in CertificateRequest message</param>
        public abstract Certificates GetCertificateToSendToServer(IList<Extension> extensionInCertificateRequest);
    }
}
