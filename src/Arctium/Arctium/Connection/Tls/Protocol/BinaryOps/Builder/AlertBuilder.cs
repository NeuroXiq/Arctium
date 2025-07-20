using Arctium.Standards.Connection.Tls.Protocol.AlertProtocol;
using System;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Builder
{
    class AlertBuilder
    {
        public static Alert FromBytes(byte[] buffer, int offset, int length)
        {
            if (length != 2) throw new Exception("Alert fragment have invalid format (must be 2 bytes)");
            return new Alert((AlertLevel)buffer[offset], (AlertDescription)buffer[offset + 1]);
        } 
    }
}
