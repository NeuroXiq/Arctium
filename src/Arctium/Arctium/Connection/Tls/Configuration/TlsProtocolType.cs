using System;

namespace Arctium.Connection.Tls.Configuration
{
    [Flags]
    public enum TlsProtocolType
    {
        Tls11,
        Tls12,
        Tls13
    }
}
