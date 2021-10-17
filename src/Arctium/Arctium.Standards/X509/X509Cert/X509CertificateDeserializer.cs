using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Standards.X509.Mapping;
using System;
using Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;

namespace Arctium.Standards.X509.X509Cert
{
    public class X509CertificateDeserializer
    {
        X509CertificateModelDecoder certRootNodeDecoder;
        X509CertificateMapper certificateMapper;

        public X509CertificateDeserializer()
        {
            certRootNodeDecoder = new X509CertificateModelDecoder();
            certificateMapper = new X509CertificateMapper();
        }

        public X509Certificate FromPem(string filename)
        {
            //PemFile pemfile = PemFile.FromFile(filename);   

            //FromBytes(pemfile.DecodedData);
            return null;
        }

        public X509Certificate FromBytes(byte[] data)
        {
            
            X509Certificate result;
            var decoded = DerDeserializer.Deserialize(data, 0);
            DerTypeDecoder derTypesDecoder = new DerTypeDecoder(data);
            var certificateModel = certRootNodeDecoder.Decode(derTypesDecoder, decoded);

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
