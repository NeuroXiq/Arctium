using Arctium.Connection.Tls.Tls12.Configuration;
using Arctium.Connection.Tls.Tls12.Configuration.TlsExtensions;

namespace Arctium.Connection.Tls
{
    public class TlsConnectionResult
    {
        public TlsHandshakeExtension[] ExtensionsResult;
        public Tls12Session Session;
        public TlsStream TlsStream;
    }
}
