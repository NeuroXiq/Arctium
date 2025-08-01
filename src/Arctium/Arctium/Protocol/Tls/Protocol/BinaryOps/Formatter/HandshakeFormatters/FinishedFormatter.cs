﻿using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class FinishedFormatter : HandshakeFormatterBase
    {
        public override int GetBytes(byte[] buffer, int offset, Handshake handshakeMsg)
        {
            Finished finished = (Finished)handshakeMsg;

            Buffer.BlockCopy(finished.VerifyData, 0, buffer, offset, finished.VerifyData.Length);

            return finished.VerifyData.Length;
        }

        public override int GetLength(Handshake handshake)
        {
            return ((Finished)handshake).VerifyData.Length;
        }
    }
}