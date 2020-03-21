using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Serialization.X690.BER.BuildInDecoders.Primitive
{
    public class PrintableStringDecoder : IX690Decoder<PrintableString>
    {
        public PrintableString Decode(byte[] buffer, long offset, long length)
        {
            string result = System.Text.Encoding.ASCII.GetString(buffer, (int)offset, (int)length);

            return new PrintableString(result);
        }
    }
}
