using Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Constructed;
using Arctium.Encoding.IDL.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690.DER
{
    public static class DerBuildInDecoders
    {
        public static IPrimitiveDecoder[] CreatePrimitiveDecoders()
        {
            List<IPrimitiveDecoder> primitiveDecoders = new List<IPrimitiveDecoder>();
            // TODO Create DER encoders instead of using BER encoders in DER-encoding
            primitiveDecoders.Add(new IntegerDecoder());
            primitiveDecoders.Add(new OidDecoder());
            primitiveDecoders.Add(new NullDecoder());
            primitiveDecoders.Add(new PrintableStringDecoder());
            primitiveDecoders.Add(new UTCTimeDecoder());
            primitiveDecoders.Add(new BitstringDecoder());
            primitiveDecoders.Add(new BooleanDecoder());
            primitiveDecoders.Add(new OctetStringDecoder());
            primitiveDecoders.Add(new UTF8StringDecoder());

            return primitiveDecoders.ToArray();
        }

        public static IConstructorDecoder[] CreateConstructorDecoders()
        {
            List<IConstructorDecoder> constructors = new List<IConstructorDecoder>();
            // TODO Create DER encoders instead of using BER encoders in DER-encoding
            constructors.Add(new BerSequenceDecoder());
            constructors.Add(new BerSetDecoder());

            return constructors.ToArray();
        }
    }
}
