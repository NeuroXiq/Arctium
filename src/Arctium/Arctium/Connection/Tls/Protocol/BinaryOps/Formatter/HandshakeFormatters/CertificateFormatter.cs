using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class CertificateFormatter
    {
        public CertificateFormatter() { }


        public byte[] GetBytes(Certificate certificate)
        {
            //X509Chain ch = new X509Chain();
            //ch.Build(certificate.ANS1Certificate);
            List<byte[]> certBytes = new List<byte[]>();
            int certsLength = 0;
            foreach (var c in certificate.ANS1Certificates)
            {
                byte[] cbytes = c.GetRawCertData();
                certBytes.Add(cbytes);
                certsLength += cbytes.Length;
            }
            byte[] result = new byte[(3 * certificate.ANS1Certificates.Length) + certsLength + 3];
            NumberConverter.FormatUInt24(result.Length - 3, result, 0);

            int curWrite = 0;

            foreach (var c in certBytes)
            {
                NumberConverter.FormatUInt24(c.Length, result, curWrite);
                Buffer.BlockCopy(c, 0, result, curWrite + 3, c.Length);
                curWrite += c.Length + 3;
            }


            return result;
        }
    }
}
