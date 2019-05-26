using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    class ServerHelloBuilder : HandshakeBuilderBase
    {
        struct Offsets
        {
            public int MinVer;
            public int MajVer;
            public int Rand;
            public int SesIDLen;
            public int SesID;
            public int CipSuite;
            public int ComprMeth;
        }

        public ServerHelloBuilder() { }


        public override Handshake BuildFromBytes(byte[] buffer, int offset, int length)
        {
            ServerHello hello = new ServerHello();
            Offsets offsets = GetOffsets(buffer, offset);

            if (length < offsets.ComprMeth + 1 - offset)
                throw new Exception("ServerHelloBuilder excetpion. Invalid length. Cannot build");


            hello.ProtocolVersion = new ProtocolVersion(buffer[offsets.MajVer], buffer[offsets.MinVer]);
            hello.Random = new byte[32];
            Buffer.BlockCopy(buffer, offsets.Rand, hello.Random, 0, 32);
            int sesIdLength = buffer[offsets.SesIDLen];
            hello.SessionID = new byte[sesIdLength];
            Buffer.BlockCopy(buffer, offsets.SesID, hello.SessionID, 0, sesIdLength);
            hello.CipherSuite = (CipherSuite)(NumberConverter.ToUInt16(buffer, offsets.CipSuite));
            hello.CompressionMethod = (CompressionMethod)(buffer[offsets.ComprMeth]);

            return hello;
        }

        private Offsets GetOffsets(byte[] buffer, int baseOffset)
        {
            Offsets o = new Offsets();

            o.MajVer = 0 + baseOffset;
            o.MinVer = 1 + baseOffset;
            o.Rand = 2 + baseOffset;
            o.SesIDLen = 34 + baseOffset;
            o.SesID = 35 + baseOffset;
            o.CipSuite = (int)buffer[o.SesIDLen] + o.SesID;
            o.ComprMeth = o.CipSuite + 2;

            return o;
        }
    }
}
