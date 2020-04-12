using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class UTF8StringDecoder : IDerTypeDecoder<UTF8String>
    {
        public UTF8String Decode(byte[] buffer, long offset, long length)
        {
            if (length == 0) return new UTF8String("");

            string decoded = System.Text.Encoding.UTF8.GetString(buffer, (int)offset, (int)length);

            return new UTF8String(decoded);
        }
    }
}
