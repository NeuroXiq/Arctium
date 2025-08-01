using Arctium.Protocol.Tls.Tls12.Configuration;
using Arctium.Protocol.Tls.Tls12.Configuration.TlsExtensions;

namespace Arctium.Protocol.Tls
{
    public class TlsConnectionResult
    {
        public TlsHandshakeExtension[] ExtensionsResult;
        public Tls12Session Session;
        public TlsStream TlsStream;
    }
}
