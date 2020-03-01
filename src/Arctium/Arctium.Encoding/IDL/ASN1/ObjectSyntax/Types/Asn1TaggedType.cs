
namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types
{
    public abstract class Asn1TaggedType
    {
        public Tag Tag;

        public virtual object Value { get; set; }

        protected Asn1TaggedType(Tag tag, object value)
        {
            Tag = tag;
            Value = value;
        }
        protected Asn1TaggedType(Tag tag)
        {
            Tag = tag;
        }
    }
}
