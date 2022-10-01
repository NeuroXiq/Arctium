using Arctium.Standards.Connection.Tls.Tls12.Configuration;
using Arctium.Standards.Connection.Tls.Tls12.Configuration.TlsExtensions;

namespace Arctium.Standards.Connection.Tls
{
    public class TlsConnectionResult
    {
        public TlsHandshakeExtension[] ExtensionsResult;
        public Tls12Session Session;
        public TlsStream TlsStream;
    }
}
