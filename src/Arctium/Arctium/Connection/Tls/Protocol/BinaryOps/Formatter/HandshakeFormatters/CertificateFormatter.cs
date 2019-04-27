using Arctium.Connection.Tls.Protocol.HandshakeProtocol;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters
{
    class CertificateFormatter
    {
        public CertificateFormatter() { }


        public byte[] GetBytes(Certificate certificate)
        {
            X509Chain ch = new X509Chain();
            ch.Build(certificate.ANS1Certificate);


            byte[] certVector = FormatCert(certificate.ANS1Certificate);


            byte[] formatted = new byte[certVector.Length + 3];

            NumberConverter.FormatUInt24(certVector.Length, formatted, 0);
            Array.Copy(certVector, 0, formatted, 3, certVector.Length);

            return formatted;
        }

        private byte[] FormatCert(X509Certificate2 aNS1Certificate)
        {
            byte[] certBytes = aNS1Certificate.GetRawCertData();

            byte[] certElement = new byte[certBytes.Length + 3];

            NumberConverter.FormatUInt24(certBytes.Length,certElement,0);
            Array.Copy(certBytes, 0, certElement, 3, certBytes.Length);

            return certElement;

        }
    }
}
