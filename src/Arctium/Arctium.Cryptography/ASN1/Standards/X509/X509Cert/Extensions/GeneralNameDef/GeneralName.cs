namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions.GeneralNameDef
{
    public class GeneralName
    {
        public GeneralNameType NameType { get; private set; }

        protected GeneralName(GeneralNameType nameType)
        {
            NameType = nameType;
        }

        // TODO X509 define strict types
        public object innerValue;
    }
}
