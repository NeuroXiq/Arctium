using Arctium.Cryptography.FileFormat.PEM;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping;
using Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public class X509CertificateDeserializer
    {

        
        X509CertificateMapper certificateMapper;

        public X509CertificateDeserializer()
        {
            
            certificateMapper = new X509CertificateMapper();
        }

        public X509Certificate FromPem(string filename)
        {
            PemFile pemfile = PemFile.FromFile(filename);   

            FromBytes(pemfile.DecodedData);
            return null;
        }

        public object FromBytes(byte[] data)
        {
            DerDeserializer decoder = new DerDeserializer(data);
            var decoded = decoder.Deserialize();

            var certificateModel = (new X509CertificateModelNodeDecoder()).Decode(decoded[0]);
            
            X509Certificate certificate = new X509CertificateMapper().MapFromModel(certificateModel);

            return null;
        }
    }
}
