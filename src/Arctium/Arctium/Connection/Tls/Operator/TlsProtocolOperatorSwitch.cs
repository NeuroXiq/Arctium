using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Operator.Tls12Operator;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Operator
{
    class TlsProtocolOperatorSwitch
    {
        public static TlsProtocolOperator OpenServerSession(Stream innerStream, TlsServerConfig serverConfig)
        {
            Tls12ServerConfig config = DefaultConfigurations.CreateDefaultTls12ServerConfig();
            config.Certificates = new X509Certificate2[] { new X509Certificate2("D:\\test.pfx", "test") };


            Tls12ServerOperator o = Tls12ServerOperator.OpenNewSession(config, innerStream);

            o.OpenSession();
            return o;
        }
    }
}