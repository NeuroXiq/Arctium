using Arctium.Connection.Tls.CryptoConfiguration;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Configuration
{
    class Tls12ServerConfig
    {
        public object SessionCache;
        public X509Certificate[] Certificates;

        ///<summary>Indicates signature algorithm that can use key in certificate</summary>
        SignatureAlgorithm SignatureAlgorithm;
    }
}
