﻿using System;

namespace Arctium.Protocol.Tls.Tls12.Configuration
{
    [Flags]
    public enum TlsProtocolVersion
    {
        Tls11,
        Tls12,
        Tls13
    }
}
