using System;

namespace Arctium.Connection.Tls.Configuration
{
    [Flags]
    public enum TlsProtocolVersion
    {
        Tls11,
        Tls12,
        Tls13
    }
}
