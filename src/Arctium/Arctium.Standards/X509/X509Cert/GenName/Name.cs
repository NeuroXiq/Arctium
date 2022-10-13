using Arctium.Standards.ASN1.Shared;
using Arctium.Standards.X501.Types;

namespace Arctium.Standards.X509.X509Cert.GenName
{
    public class Name : ChoiceObj<Name.NameType>
    {
        static readonly TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(RelativeDistinguishedName[]), NameType.RDNSequence)
        };

        protected override TypeDef[] ChoiceObjConfig => config;

        public enum NameType { RDNSequence };

        public Name(RelativeDistinguishedName[] rndSequence)
        {
            Set(NameType.RDNSequence, rndSequence);
        }
    }
}
