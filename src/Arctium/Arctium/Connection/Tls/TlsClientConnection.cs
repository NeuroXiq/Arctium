using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Operator;
using Arctium.Connection.Tls.Operator.Tls12Operator;
using System.IO;

namespace Arctium.Connection.Tls
{
    public class TlsClientConnection
    {
        Tls12ClientConfig config;

        public TlsClientConnection() { }

        public TlsConnectionResult Connect(Stream innerStream)
        {
            config = new Tls12ClientConfig();
            config.EnableCipherSuites = DefaultConfigurations.CreateDefaultTls12CipherSuites();
            config.Extensions = null;

            Tls12ClientOperator clientOperator = new Tls12ClientOperator(config, innerStream);
            clientOperator.OpenSession();


            TlsConnectionResult result = new TlsConnectionResult();
            result.ExtensionsResult = null;
            result.Session = null;
            result.TlsStream = new TlsStream(clientOperator);

            return result;
        }

        public int Read(byte[] buffer, int offset, int length)
        {
            return 0;
        }

        public void Write(byte[] buffer, int offset, int length)
        {

        }
    }
}
