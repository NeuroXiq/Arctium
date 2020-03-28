namespace Arctium.Cryptography.ASN1.Standards.X509.Types
{
    public enum GeneralNameType
    {
        OtherName,
        Rfc822Name,
        DNSName,
        X400Address,

        /// <summary>
        /// X501 Name
        /// </summary>
        DirectoryName,
        EdiPartyName,
        UniformResourceIdentifier,
        IPAddress,
        RegisteredID
    }
}
