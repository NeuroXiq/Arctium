using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.QUICv1Impl.Model
{
    internal enum LongPacketType: byte
    {
        Initial = 0x00,
        ZeroRTT = 0x01,
        Handshake = 0x02,
        Retry = 0x03
    }
}
