using ASN1Types = Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;

namespace Arctium.Encoding.IDL.ASN1.Mapper.Attributes
{
    [System.AttributeUsage(System.AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public class Asn1TypeAttribute : System.Attribute
    {
        public ASN1Types.Tag Tag { get; private set; }
        public virtual object Parameters { get; private set; }
        public Asn1TypeAttribute(ASN1Types.Tag tag, object parameters)
        {
            Tag = tag;
            Parameters = parameters;
        }
    }
}
