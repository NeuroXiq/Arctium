using Arctium.Cryptography.ASN1.ObjectSyntax.Types;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;

namespace Arctium.Cryptography.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class UTF8StringDecoder : IX690Decoder<UTF8String>
    {
        public UTF8String Decode(byte[] buffer, long offset, long length)
        {
            if (length == 0) return new UTF8String("");

            string decoded = System.Text.Encoding.UTF8.GetString(buffer, (int)offset, (int)length);

            return new UTF8String(decoded);
        }
    }
}
