using System;

namespace Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct PrintableString
    {
        public string Value;
        public PrintableString(string stringValue)
        {
            if (stringValue == null) throw new ArgumentNullException(nameof(stringValue));
            Value = stringValue;
        }

        public static implicit operator PrintableString(string stringValue) => new PrintableString(stringValue);
        public static implicit operator string(PrintableString printableString) => printableString.Value;

        public override string ToString()
        {
            return Value;
        }

    }
}
