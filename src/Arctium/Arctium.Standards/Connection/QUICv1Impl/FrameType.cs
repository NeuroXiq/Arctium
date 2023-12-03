using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    internal enum FrameType : byte
    {
        Padding = 0x00,
        Ping = 0x01,
        Ack2 = 0x02,
        Ack3 = 0x03,
        ResetStream = 0x04,
        StopSending = 0x05,
        Crypto = 0x06,
        NewToken = 0x07 ,
        Stream = 0x08,
        MaxData = 0x10 ,
        MaxStreamData = 0x11 ,
        MaxStreams2 = 0x12,
        MaxStreams3 = 0x13,
        DataBlocked = 0x14 ,
        StreamDataBlocked = 0x15 ,
        StreamsBlocked6 = 0x16,
        StreamsBlocked7 = 0x17,
        NewConnectionId = 0x18 ,
        RetireConnectionId = 0x19 ,
        PathChallenge = 0x1a ,
        PathResponse = 0x1b ,
        ConnectionCloseC = 0x1c,
        ConnectionCloseD = 0x1d,
        HandshakeDone = 0x1e
    }
}
