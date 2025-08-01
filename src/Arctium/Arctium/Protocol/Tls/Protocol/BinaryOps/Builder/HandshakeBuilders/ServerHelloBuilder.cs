using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol;
using Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Enum;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
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
            public int Extensions;
        }

        ExtensionBuilder extensionsBuilder;

        public ServerHelloBuilder()
        {
            extensionsBuilder = new ExtensionBuilder();
        }


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


            int lengthBeforeExtensions = offsets.Extensions - offset;
            int extensionsBlockLength = length - lengthBeforeExtensions;

            hello.Extensions = extensionsBuilder.GetExtensions(buffer, offsets.Extensions, extensionsBlockLength);


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
            o.Extensions = o.ComprMeth + 1;

            return o;
        }
    }
}
