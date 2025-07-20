using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders
{
    public class PrintableStringDecoder : IDerTypeDecoder<PrintableString>
    {
        public PrintableString Decode(byte[] buffer, long offset, long length)
        {
            string result = System.Text.Encoding.ASCII.GetString(buffer, (int)offset, (int)length);

            return new PrintableString(result);
        }
    }
}
