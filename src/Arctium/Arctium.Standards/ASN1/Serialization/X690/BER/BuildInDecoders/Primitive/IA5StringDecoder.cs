using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;
using System.Text;

namespace Arctium.Standards.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class IA5StringDecoder : IX690Decoder<IA5String>
    {
        public IA5String Decode(byte[] buffer, long offset, long contentLength)
        {
            return Encoding.UTF8.GetString(buffer, (int)offset, (int)contentLength);
        }
    }
}
