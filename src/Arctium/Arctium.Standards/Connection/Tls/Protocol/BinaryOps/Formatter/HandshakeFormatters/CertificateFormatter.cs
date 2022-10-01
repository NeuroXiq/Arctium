using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol;
using System;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class CertificateFormatter : HandshakeFormatterBase
    {
        public CertificateFormatter() { }

        public override int GetBytes( byte[] buffer, int offset, Handshake handshakeMessage)
        {
            Certificate certificateMsg = (Certificate)handshakeMessage;
            int totalLength = 0;

            int vectorLengthOffset = 3 + offset;
            int vectorDataOffset = vectorLengthOffset + 3;

            foreach (var cert in certificateMsg.ANS1Certificates)
            {
                // copy certificate bytes to buffer
                Buffer.BlockCopy(cert.RawData, 0, buffer, vectorDataOffset, cert.RawData.Length);

                //insert certificate length before data bytes (data copied above)
                NumberConverter.FormatUInt24(cert.RawData.Length, buffer, vectorLengthOffset);

                //shift offsets
                vectorLengthOffset += cert.RawData.Length + 3;
                vectorDataOffset += cert.RawData.Length + 3;

                totalLength += cert.RawData.Length + 3;
            }

            //length of all certificate vectors
            NumberConverter.FormatUInt24(totalLength, buffer, offset);

            return totalLength + 3; // 3 bytes of length of all certs vectors preceeding them
        }

        public override int GetLength(Handshake handshake)
        {
            Certificate cert = (Certificate)handshake;


            int totalLength = 0;

            totalLength += 3; // 3 length bytes of the all cert vectors

            //
            // every certificate data is preceeded by 3 byte length ('vector')
            // compute only this length of all 3-byte lengths for every cert

            totalLength += (3 * cert.ANS1Certificates.Length);

            //now compute only cert data lengths

            foreach (var curCert in cert.ANS1Certificates)
            {
                totalLength += curCert.RawData.Length;
            }

            return totalLength;
        }
    }
}
/* Certificate certificate = (Certificate)handshakeMessage;

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

            int curWrite = 3;

            foreach (var c in certBytes)
            {
                NumberConverter.FormatUInt24(c.Length, result, curWrite);
                Buffer.BlockCopy(c, 0, result, curWrite + 3, c.Length);
                curWrite += c.Length + 3;
            }


            */
