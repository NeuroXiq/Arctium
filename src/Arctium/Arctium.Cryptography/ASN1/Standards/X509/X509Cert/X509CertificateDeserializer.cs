using Arctium.Cryptography.FileFormat.PEM;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping;
using Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders;
using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public class X509CertificateDeserializer
    {
        DerDeserializer derDeserializer;
        X509CertificateModelNodeDecoder certRootNodeDecoder;
        X509CertificateMapper certificateMapper;

        public X509CertificateDeserializer()
        {
            derDeserializer = new DerDeserializer();
            certRootNodeDecoder = new X509CertificateModelNodeDecoder();
            certificateMapper = new X509CertificateMapper();
        }

        public X509Certificate FromPem(string filename)
        {
            PemFile pemfile = PemFile.FromFile(filename);   

            FromBytes(pemfile.DecodedData);
            return null;
        }

        public X509Certificate FromBytes(byte[] data)
        {
            X509Certificate result;
            var decoded = derDeserializer.Deserialize(data)[0];
            var certificateModel = certRootNodeDecoder.Decode(decoded);

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
