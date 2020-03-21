using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;
using System.Text;

namespace Arctium.Cryptography.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    class UniversalStringDecoder : IX690Decoder<UniversalString>
    {
        public UniversalString Decode(byte[] buffer, long offset, long length)
        {
            string decodedString = Encoding.UTF8.GetString(buffer, (int)(offset), (int)length);

            
            return new UniversalString(decodedString);
        }
    }
}
