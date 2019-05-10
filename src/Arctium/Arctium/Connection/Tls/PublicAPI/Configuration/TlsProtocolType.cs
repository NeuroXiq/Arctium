using System;

namespace Arctium.Connection
{
    [Flags]
    public enum TlsType
    {
        Tls11,
        Tls12,
        Tls13
    }
}
