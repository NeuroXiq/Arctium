using Arctium.Cryptography.ASN1.ObjectSyntax.Exceptions;

namespace Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct UTF8String
    {
        private string Value;
        public UTF8String(string stringValue)
        {
            Value = stringValue;
        }


        public static implicit operator UTF8String(string stringValue) => new UTF8String(stringValue);
        public static implicit operator string(UTF8String printableString) => printableString.Value;

        public override string ToString()
        {
            return Value;
        }
    }
}
