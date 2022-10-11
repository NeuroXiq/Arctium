using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Standards.X509.Mapping;
using System;
using Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.FileFormat.PEM;

namespace Arctium.Standards.X509.X509Cert
{
    public class X509CertificateDeserializer
    {
        const string BeginCertificatePemLabel = "CERTIFICATE";
        X509CertificateModelDecoder certRootNodeDecoder;
        X509CertificateMapper certificateMapper;

        public X509CertificateDeserializer()
        {
            certRootNodeDecoder = new X509CertificateModelDecoder();
            certificateMapper = new X509CertificateMapper();
        }

        public X509Certificate FromPem(string filename)
        {
            PemFile pemfile = PemFile.FromFile(filename);
            if (pemfile.BeginLabel != BeginCertificatePemLabel)
                throw new ArgumentException(
                    string.Format("Pem file start label is not equal to '{0}'. Current label: {1}", BeginCertificatePemLabel, pemfile.BeginLabel));

            return FromBytes(pemfile.DecodedData);
        }

        public X509Certificate FromBytes(byte[] data)
        {
            X509Certificate result;
            var decodedContext = DerDeserializer.Deserialize2(data, 0);
            var certificateModel = certRootNodeDecoder.Decode(decodedContext);

            result = certificateMapper.MapFromModel(certificateModel);
            try
            {
              
            }
            catch (Exception e)
            {
                throw;
            }

            return result;
        }
    }
}
