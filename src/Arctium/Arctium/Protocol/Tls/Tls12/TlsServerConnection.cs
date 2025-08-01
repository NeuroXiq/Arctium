using Arctium.Protocol.Tls.Tls12.Configuration;
using Arctium.Protocol.Tls.Tls12.Configuration.TlsExtensions;
using Arctium.Protocol.Tls.Tls12.Operator.Tls12Operator;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Protocol.Tls
{
    public class TlsServerConnection
    {
        Tls12ServerConfig tls12Serverconfig;
        TlsProtocolVersion version;
        

        public TlsServerConnection(X509Certificate2 cert) : this(cert, TlsProtocolVersion.Tls12, null)
        {
            //this.config = DefaultConfigurations.CreateDefaultTls12ServerConfig();
            //config.Tls11ServerConfig.
        }

        public TlsServerConnection(X509Certificate2 cert, TlsProtocolVersion version) : this(cert, version, null)
        {

        }

        public TlsServerConnection(X509Certificate2 cert, TlsProtocolVersion version, TlsHandshakeExtension[] extensionsList)
        {
            if (cert == null) throw new ArgumentNullException("cert");
            if (version != TlsProtocolVersion.Tls12)
                throw new NotSupportedException("Current implementation supprots only Tls12");
            //if (extensionsList != null) throw new NotSupportedException("Extensions not supported yet (must be set to null) ");

            if (!cert.HasPrivateKey) throw new ArgumentException("certificate must contain private key");
            if (cert.GetRSAPrivateKey() == null) throw new ArgumentException("certificate must contain RSA private key");
            if (cert.GetRSAPublicKey() == null) throw new ArgumentException("certificate must contain RSA public key");

            this.version = version;

            tls12Serverconfig = new Tls12ServerConfig();
            tls12Serverconfig.Certificates = new X509Certificate2[] { cert };
            tls12Serverconfig.EnableCipherSuites = DefaultConfigurations.CreateDefaultTls12CipherSuites();
            tls12Serverconfig.HandshakeExtensions = extensionsList;
        }

        ///<summary>Accept new connection from specified stream</summary>
        public TlsConnectionResult Accept(Stream innerStream)
        {
            Tls12ServerOperator tls12Operator = new Tls12ServerOperator(tls12Serverconfig, innerStream);

            //handshake
            return tls12Operator.OpenSession();

        }

      
    }
}
