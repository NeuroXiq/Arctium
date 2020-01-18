using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders
{
    class CertificateBuilder : HandshakeBuilderBase
    {
        public CertificateBuilder() { }

       
        public override Handshake BuildFromBytes(byte[] buffer, int offset, int length)
        {
            List<X509Certificate2> certs = new List<X509Certificate2>();

            int total = 3;
            do
            {
                int certBytesLen = (int)NumberConverter.ToUInt24(buffer, offset + total);
                byte[] curCertBytes = new byte[certBytesLen];
                Buffer.BlockCopy(buffer, offset + total + 3, curCertBytes, 0, certBytesLen);

                var ctt = new X509Certificate2(curCertBytes);

                certs.Add(ctt);

                total += 3 + certBytesLen;


            } while (total < length - 3);


            return new Certificate(certs.ToArray());

        }
    }
}
