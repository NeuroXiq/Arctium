using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.Documents.Certificates.X509Certificates.X509v3Certificate.Asn1
{
    public class Asn1VersionType : Asn1TaggedType, IAsn1StrictType<Integer>
    {
        public Asn1VersionType(object value) : base(new Tag(TagClass.Private, 0), value)
        {

        }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }

        public Integer TypedValue { get; set; }

        public void SetAsStrict(object value)
        {
            if (!(value is Integer))
            {
                throw InvalidStrictTypeException.Create<Asn1VersionType, IAsn1StrictType<Integer>>(value);
            }

            TypedValue = (Integer)value;
        }
    }
}
