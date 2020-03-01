using Arctium.Cryptography.Documents.Certificates.Exceptions;
using Arctium.Cryptography.Documents.Certificates.X509Certificates.X509v3Certificate.Asn1;
using Arctium.Encoding.FileFormat.Exceptions;
using Arctium.Encoding.FileFormat.PEM;
using Arctium.Encoding.IDL.ASN1.Serialization;
using Arctium.Encoding.IDL.ASN1.Serialization.X690;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.BER;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using System;
using System.Collections.Generic;

namespace Arctium.Cryptography.Documents.Certificates.X509Certificates.X509v3Certificate
{
    public static class X509v3CertificateEncoding
    {
        const string pemCertLabel = "CERTIFICATE";

        public static X509v3Certificate FromPem(string fileName)
        {
            PemFile pemFile;
            try
            {
                pemFile = PemFile.FromFile(fileName);
            }
            catch (InvalidFileFormatException e)
            {
                throw new InvalidCertFileException(e.Message);
            }

            if ((pemFile.BeginLabel != pemCertLabel) || (pemFile.EndLabel != pemCertLabel))
            {
                throw new InvalidCertDataException("Invalid label at begin/end of the pem file");
            }

            X509v3Certificate certificate = Deserialize(pemFile.DecodedData, Asn1EncodingRule.DER);

            return certificate;
        }

        public static X509v3Certificate Deserialize(byte[] rawBytes, Asn1EncodingRule encodingType)
        {
            switch (encodingType)
            {
                case Asn1EncodingRule.BER:
                case Asn1EncodingRule.DER:
                    return DecodeBer(rawBytes);
                default: throw new NotSupportedException($"{encodingType.ToString()} is not supported");
            }
        }

        private static X509v3Certificate DecodeBer(byte[] rawBytes)
        {
            //BerDeserializer deserializer = new BerDeserializer();
            //deserializer.AddExternalDecoder(new Asn1VersionDecoder());
            //deserializer.Decode(rawBytes);

            List<IConstructorDecoder> certDecoders = new List<IConstructorDecoder>();
            certDecoders.Add(new Asn1VersionDecoder());

            DerDeserializer deserializer = new DerDeserializer(certDecoders.ToArray());

            var result = deserializer.Deserialize(rawBytes);

            return null;
        }
    }
}
