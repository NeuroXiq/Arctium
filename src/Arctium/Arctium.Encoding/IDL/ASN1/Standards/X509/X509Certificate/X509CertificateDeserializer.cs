using Arctium.Encoding.FileFormat.PEM;
using Arctium.Encoding.IDL.ASN1.Serialization.X690;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Decoders;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Mapping;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Model;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Types;
using Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate.Mapping;
using System.Collections.Generic;


namespace Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate
{
    public class X509CertificateDeserializer
    {
        IPrimitiveDecoder[] x509PrimitiveDecoders;
        IConstructorDecoder[] x509ConstructorDecoders;

        DerDeserializer deserialier;
        X509ModelMapper modelMapper;
        X509CertificateMapper certificateMapper;

        public X509CertificateDeserializer()
        {
            List<IPrimitiveDecoder> primitiveDecoders = new List<IPrimitiveDecoder>();

            List<IConstructorDecoder> constructorDecoders = new List<IConstructorDecoder>();

            constructorDecoders.Add(new VersionDecoder());
            constructorDecoders.Add(new ExtensionsDecoder());

            x509PrimitiveDecoders = primitiveDecoders.ToArray();
            x509ConstructorDecoders = constructorDecoders.ToArray();

            deserialier = new DerDeserializer(x509ConstructorDecoders, x509PrimitiveDecoders);
            modelMapper = new X509ModelMapper();
            certificateMapper = new X509CertificateMapper();
        }

        public X509Certificate FromPem(string filename)
        {
            PemFile pemfile = PemFile.FromFile(filename);   

            return FromBytes(pemfile.DecodedData);

        }

        public X509Certificate FromBytes(byte[] rawDerData)
        {
            X690DeserializationResult decodingResult = deserialier.Deserialize(rawDerData);
            X509CertificateModel model = modelMapper.MapFromResult(decodingResult.RootDecodedValue);
            X509Certificate certificate = certificateMapper.MapFromModel(model);

            return certificate;
        }
    }
}
