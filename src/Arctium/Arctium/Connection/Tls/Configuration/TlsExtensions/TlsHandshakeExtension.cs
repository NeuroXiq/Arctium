using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    //
    // Hides internal representation of the handshake extensions to public usage
    //

    class TlsHandshakeExtension
    {
        HandshakeExtensionType internalExtensionType;

        protected TlsHandshakeExtension(HandshakeExtensionType type)
        {
            internalExtensionType = type;
        }
    }
}
