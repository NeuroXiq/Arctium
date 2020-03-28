namespace Arctium.Cryptography.ASN1.Standards.X501.Types
{
    public enum AttributeType
    {
        // type that receiver MUST process ()x509
        Country,
        Organization,
        OrganizationalUnit,
        DistinguishedNameQualifier,
        StateOrProvinceName,
        CommonName,
        SerialNumber,

        DomainComponent,

        // additional types that receiver SHOULD process ()x509
        Locality,
        Title,
        Surname,
        GivenName,
        Initials,
        Pseudonym,
        GenerationQualifier,

        /// <summary>
        /// LEGACY attribute
        /// </summary>
        Email
    }
}
