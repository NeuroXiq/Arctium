using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Model;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Types
{
    public class Extensions : Asn1TaggedType, IAsn1StrictType<Sequence>
    {
        
        public Extensions(Sequence value) : base(X509Type.ExtensionsTag, value) { }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }

        public Sequence TypedValue { get; set; }

        public void SetAsStrict(object value)
        {
            if (!(value is Sequence))
            {
                throw InvalidStrictTypeException.Create<Extensions, Sequence>(value);
            }

            TypedValue = (Sequence)value;

        }
    }
}
