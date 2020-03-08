using System;
using Arctium.Encoding.FileFormat.PEM;
using Arctium.Encoding.IDL.ASN1.Standards.X509;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Model;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Types;

namespace Arctium.Cryptography.Documents.Certificates.X509Certificates
{
    public class X509CertDecoder
    {
        public X509Certificate FromPem(string fileName)
        {
            PemFile pemFile = PemFile.FromFile(fileName);

            byte[] derRawData = pemFile.DecodedData;

            X509Deserializer deserializer = new X509Deserializer();
            X509CertificateModel model = deserializer.FromDer(derRawData);

            X509Certificate certificate = MapFromModel(model);

            return certificate;
        }

        private X509Certificate MapFromModel(X509CertificateModel model)
        {
            throw new NotImplementedException();
        }
    }
}
