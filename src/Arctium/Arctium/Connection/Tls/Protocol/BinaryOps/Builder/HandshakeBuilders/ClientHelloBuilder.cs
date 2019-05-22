using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    class ClientHelloBuilder
    {
        struct Format
        {
            public int majVer;
            public int minVer;
            public int Rand;
            public int SesIdLen;
            public int SesId;
            public int CipSuiteLen;
            public int CipSuite;
            public int ComprMeth;
            public int ComprMethLen;
            public int Exts;
            public int ExtsLen;
        }

        public ClientHelloBuilder()
        {

        }


        public ClientHello BuildClientHello(byte[] buffer, int clientHelloOffset, int bytesInMessage)
        {
            Format format = GetFormat(buffer, clientHelloOffset, bytesInMessage);

            int sessionIdLength = -1;
            int cipherSuiteLength = -1;
            int compressionMethodsLength = -1;


            int sessionIdLengthOffset = 34 + clientHelloOffset;
            if (sessionIdLengthOffset >= bytesInMessage) throw new Exception("invalid length of client hello");
            sessionIdLength = buffer[sessionIdLengthOffset];

            int cipherSuiteLengthOffset = sessionIdLengthOffset + 1 + sessionIdLength;
            if (cipherSuiteLengthOffset >= bytesInMessage) throw new Exception("invalid length of client hello");
            cipherSuiteLength = NumberConverter.ToUInt16(buffer, cipherSuiteLengthOffset);

            int compressionMethodLengthOffset = cipherSuiteLengthOffset + 2 + cipherSuiteLength;
            if (compressionMethodLengthOffset >= bytesInMessage) throw new Exception("invalid length of client hello");
            compressionMethodsLength = buffer[compressionMethodLengthOffset];

            if (cipherSuiteLength % 2 == 1) throw new Exception("invalid length of cipher suites");

            byte majorVersion = buffer[clientHelloOffset + 0];
            byte minorVersion = buffer[clientHelloOffset + 1];

            byte[] sessionIdBytes = new byte[sessionIdLength];
            Array.Copy(buffer, sessionIdLengthOffset + 1, sessionIdBytes, 0, sessionIdLength);

            ClientHello clientHello = new ClientHello();
            clientHello.ClientVersion = new ProtocolVersion(majorVersion, minorVersion);
            clientHello.Random = GetHelloRandom(buffer, clientHelloOffset + 2);
            clientHello.SessionID = sessionIdBytes ;//new SessionID(sessionIdBytes);
            clientHello.CipherSuites = GetCipherSuite(buffer, cipherSuiteLength, cipherSuiteLengthOffset + 2);
            clientHello.CompressionMethods = BuildCompressionMethods(buffer, compressionMethodLengthOffset + 1, compressionMethodsLength);

            return clientHello;
        }


        private Format GetFormat(byte[] buffer, int offset, int length)
        {
            Format fmt = new Format();

            int maxOffset = length + offset;

            fmt.majVer = offset;
            fmt.minVer = offset + 1;
            fmt.Rand = offset + 2;

            if (fmt.Rand + 32 > maxOffset) throw new Exception("invalid format");

            fmt.SesIdLen = buffer[fmt.Rand + 32];
            fmt.SesId = fmt.Rand + 32 + 1;

            if (fmt.SesId + fmt.SesIdLen + 1 > maxOffset) throw new Exception("invalid format");

            //length of the cipher suies
            fmt.CipSuiteLen = NumberConverter.ToUInt16(buffer, fmt.SesId + fmt.SesIdLen);
            //offset of the cipher suites
            fmt.CipSuite = fmt.SesId + fmt.SesIdLen + 2;


            if (fmt.CipSuite + fmt.CipSuiteLen > maxOffset) throw new Exception("invalid foramt");
            fmt.ComprMethLen = buffer[fmt.CipSuite + fmt.CipSuiteLen];
            fmt.ComprMeth = fmt.CipSuite + fmt.CipSuiteLen + 1;

            fmt.Exts = fmt.ComprMeth + 1;
            fmt.ExtsLen = length - (fmt.ComprMeth - offset) + 1;

            return fmt;
        }

        private CompressionMethod[] BuildCompressionMethods(byte[] buffer, int methodsOffset, int compressionMethodsLength)
        {
            CompressionMethod[] compressionMethods = new CompressionMethod[compressionMethodsLength];

            for (int i = 0; i < compressionMethodsLength; i++)
            {
                compressionMethods[i] = (CompressionMethod)buffer[methodsOffset + i];
            }

            return compressionMethods;
        }

        private CipherSuite[] GetCipherSuite(byte[] buffer, int cipherSuiteLength, int ciphersOffset)
        {
            int cipherSuiteCount = cipherSuiteLength / 2;

            CipherSuite[] ciphersSuite = new CipherSuite[cipherSuiteCount];

            for (int i = 0; i < cipherSuiteCount; i++)
            {
                int cipherOffset = ciphersOffset + (i * 2);

                int cipherSuiterNumber = (buffer[cipherOffset + 0] << 8) + 
                                         (buffer[cipherOffset + 1] << 0);

                ciphersSuite[i] = (CipherSuite)cipherSuiterNumber;
            }


            return ciphersSuite;
        }

        private byte[] GetHelloRandom(byte[] buffer, int offset)
        {
            byte[] random = new byte[32];
            Buffer.BlockCopy(buffer, offset, random, 0, 32);
            return random;
            
            //byte[] randomBytes = new byte[28];
            
            //uint gmtUnixTime = (uint)(buffer[offset + 0] << 24 |
            //                buffer[offset + 1] << 16 |
            //                buffer[offset + 2] << 8 |
            //                buffer[offset + 3] << 0);
            //for (int i = 0; i < 28; i++)
            //{
            //    randomBytes[i] = buffer[4 + offset + i];
            //}



            //return new HelloRandom(gmtUnixTime, randomBytes);
        }
    }
}
