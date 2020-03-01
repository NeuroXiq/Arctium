using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;
using System;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    class PrintableString : Asn1TaggedType, IAsn1StrictType<string>
    {
        public PrintableString(string value) : base(BuildInTag.PrintableString)
        {
            TypedValue = value;
        }

        public string TypedValue { get; set; }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }

        public void SetAsStrict(object value)
        {
            if (!(value is string))
                throw InvalidStrictTypeException.Create<PrintableString, string>(value);
            TypedValue = (string)value;
        }
    }
}
