```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - Post Handshake Client Authentication
 * 
 * How to configure Post Handshake Client Authentication
 * 
 * Can be tested with Arctium TLS 1.3 Server or any server that supports post handshake authentication
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.APIModel;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Standards.Connection.Tls.Tls13.API.Messages;
using System.Net.Sockets;
using System.Text;

namespace ConsoleAppTest
{
    // Configuration is very similar to Handshake Client Auth
    class HSClientAuth : ClientConfigPostHandshakeClientAuthentication
    {
        public override Certificates GetCertificateToSendToServer(IList<Extension> extensionInCertificateRequest)
        {
            // method needs to return list of certificates
            // or null certificate if not want to use authentication.
            // 'extensions' parameter is extensions from server

            foreach (var ext in extensionInCertificateRequest)
            {
                // cast extensions and use it if want
                switch (ext.ExtensionType)
                {
                    case ExtensionType.UnknownExtension: break;
                    case ExtensionType.OidFilters: var oids = ext as ExtensionOidFilters; break;
                    case ExtensionType.SignatureAlgorithms: var sigalgo = ext as ExtensionSignatureSchemeList; break;
                    case ExtensionType.CertificateAuthorities: break;
                    default: break;
                }
            }

            return new Certificates
            {
                // this value can be null if dont want to authenticate
                ClientCertificate = Tls13Resources.CERT_WITH_KEY_cert_secp256r1_sha256_1,
                
                //x509 chain, here is empty for purpose of this example
                ParentCertificates = new Arctium.Standards.X509.X509Cert.X509Certificate[0]
            };
        }
    }

    internal class MainProgram
    {
        static void Main()
        {
            var context = Tls13ClientContext.DefaultUnsafe();

            // configure Post Handshake Client  Authentication
            // client will send extensions that indicates that client support Post Handshake auth
            context.Config.ConfigurePostHandshakeClientAuthentication(new HSClientAuth());
            
            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();

            var stream = client.Connect(networkStream, out var info);

            // ready to go
        }
    }
}

```