using Arctium.Encoding.IDL.ASN1.Serialization.X690.DER;
using Arctium.Encoding.IDL.ASN1.Serialization.X690;
using System.Collections.Generic;

namespace Arctium.Cryptography.Documents.Certificates.X509Certificates.X509v3Certificate.Asn1
{
    static class Asn1x509v3CertDerDecoder
    {
        public static X509v3Certificate Decode(byte[] derCertData)
        {
            List<IConstructorDecoder> certDecoders = new List<IConstructorDecoder>();
            certDecoders.Add(new Asn1VersionDecoder());
            certDecoders.Add(new Asn1UniqueIdentifierDecoder());

            DerDeserializer deserializer = new DerDeserializer(certDecoders.ToArray());

            var result = deserializer.Deserialize(derCertData);



            return null;
        }
    }
}
