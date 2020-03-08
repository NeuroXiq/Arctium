using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Types
{
    /// <summary>
    ///  Contains tags defined in X509 standard
    /// </summary>
    public static class X509Type
    {
        public const long ExtensionsTagNumber = 3;
        public const long SubjectUniqueIdTagNumber = 2;
        public const long IssuerUniqueIdTagNumber = 1;
        public const long VersionTagNumber = 0;

        public static Tag ExtensionsTag => new Tag(TagClass.Private, ExtensionsTagNumber);
        public static Tag VersionTag => new Tag(TagClass.Private, VersionTagNumber);
        public static Tag IssuerUniqueIdTag => new Tag(TagClass.Private, IssuerUniqueIdTagNumber);
        public static Tag SubjectUniqueIdTag => new Tag(TagClass.Private, SubjectUniqueIdTagNumber);

    }
}
