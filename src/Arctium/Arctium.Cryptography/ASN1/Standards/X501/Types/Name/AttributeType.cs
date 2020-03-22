namespace Arctium.Cryptography.ASN1.Standards.X501.Types
{
    public enum AttributeType
    {
        // type that receiver MUST process
        Country,
        Organization,
        OrganizationalUnit,
        DistinguishedNameQualifier,
        StateOrProvinceName,
        CommonName,
        SerialNumber,

        DomainComponent,

        // additional types that receiver SHOULD process
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
