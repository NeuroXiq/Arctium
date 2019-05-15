using Arctium.Connection.Tls.CryptoConfiguration;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    class ClientHelloBuilder
    {
        public ClientHelloBuilder()
        {

        }


        public ClientHello BuildClientHello(byte[] buffer, int clientHelloOffset, int bytesInMessage)
        {
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
