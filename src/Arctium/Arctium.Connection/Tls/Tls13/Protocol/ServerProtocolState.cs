using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    public enum ServerProtocolState
    {
        Listen,
        Handshake,
        Connected
    }
}
