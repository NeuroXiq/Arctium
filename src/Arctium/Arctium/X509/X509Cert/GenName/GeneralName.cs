using Arctium.Shared.Other;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Shared;

namespace Arctium.Standards.X509.X509Cert.GenName
{
    public class GeneralName : ChoiceObj<GeneralNameType>
    {
        static readonly TypeDef[] config = new TypeDef[]
        {
            new TypeDef(typeof(OtherName), GeneralNameType.OtherName),
            new TypeDef(typeof(string), GeneralNameType.Rfc822Name),
            new TypeDef(typeof(string), GeneralNameType.DNSName),
            new TypeDef(typeof(ORAddress), GeneralNameType.X400Address),
            new TypeDef(typeof(Name), GeneralNameType.Name),
            new TypeDef(typeof(EDIPartyName), GeneralNameType.EdiPartyName),
            new TypeDef(typeof(string), GeneralNameType.UniformResourceIdentifier),
            new TypeDef(typeof(byte[]), GeneralNameType.IPAddress),
            new TypeDef(typeof(ObjectIdentifier), GeneralNameType.RegisteredID),
        };

        protected override TypeDef[] ChoiceObjConfig => config;

        internal GeneralName(GeneralNameType nameType, object innerValue)
        {
            base.Set(nameType, innerValue);
        }

        // temporary not supported until deserialization x509 implemented
        public bool IsSupported { get; private set; }
        private GeneralName() { }
        internal GeneralName RecognizedButNotSupportedNow(GeneralNameType type)
        {
            var gname = new GeneralName();
            gname.IsSupported = false;
            base.key = type;

            return gname;
        }

        public override T Get<T>()
        {
            if (!IsSupported)
                Validation.NotSupported(
                    "General name is recognied (see ValueKey property of this class) but it is " + 
                    "not supported now. Underlying value cannot be obtained");
            return base.Get<T>();
        }
    }
}
