using Arctium.Connection.Tls.Configuration;
using Arctium.Connection.Tls.Configuration.TlsExtensions;

namespace Arctium.Connection.Tls
{
    public class TlsConnectionResult
    {
        public TlsHandshakeExtension[] ExtensionsResult;
        public Tls12Session Session;
        public TlsStream TlsStream;
    }
}
