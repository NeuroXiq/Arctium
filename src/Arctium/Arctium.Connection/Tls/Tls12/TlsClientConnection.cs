using Arctium.Connection.Tls.Tls12.Configuration;
using Arctium.Connection.Tls.Tls12.Configuration.TlsExtensions;
using Arctium.Connection.Tls.Tls12.Operator.Tls12Operator;
using System.IO;

namespace Arctium.Connection.Tls
{
    public class TlsClientConnection
    {
        Tls12ClientConfig config;

        public TlsClientConnection() : this(null) { }

        public TlsClientConnection(TlsHandshakeExtension[] publicExtensions)
        {
            config = new Tls12ClientConfig();
            config.EnableCipherSuites = DefaultConfigurations.CreateDefaultTls12CipherSuites();
            config.Extensions = publicExtensions;
        }

        public TlsConnectionResult Connect(Stream innerStream)
        {
            Tls12ClientOperator clientOperator = new Tls12ClientOperator(config, innerStream);
            return clientOperator.OpenSession();
        }

        public TlsConnectionResult Connect(Stream innerStream, Tls12Session testSessionResumption)
        {
            Tls12ClientOperator clientOperator = new Tls12ClientOperator(config, innerStream);
            TlsConnectionResult result = clientOperator.OpenSession(testSessionResumption);


            return result;
        }
    }
}
