using Arctium.Encoding.IDL.ASN1.Serialization.X690;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Decoders;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Model;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Types;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509
{
    public class X509Deserializer
    {
        IPrimitiveDecoder[] x509PrimitiveDecoders;
        IConstructorDecoder[] x509ConstructorDecoders;

        DerDeserializer deserialier;
        X509ModelMapper modelMapper;

        public X509Deserializer()
        {
            List<IPrimitiveDecoder> primitiveDecoders = new List<IPrimitiveDecoder>();

            List<IConstructorDecoder> constructorDecoders = new List<IConstructorDecoder>();

            constructorDecoders.Add(new VersionDecoder());
            constructorDecoders.Add(new ExtensionsDecoder());

            x509PrimitiveDecoders = primitiveDecoders.ToArray();
            x509ConstructorDecoders = constructorDecoders.ToArray();

            deserialier = new DerDeserializer(x509ConstructorDecoders, x509PrimitiveDecoders);
            modelMapper = new X509ModelMapper();
        }

        public X509CertificateModel FromDer(byte[] rawDerData)
        {
            DerDeserializationResult decodingResult =  deserialier.Deserialize(rawDerData);

            X509CertificateModel model = modelMapper.MapFromResult(decodingResult.RootDecodedValue);

            return model;
        }
    }
}
