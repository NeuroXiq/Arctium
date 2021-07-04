namespace Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions
{
    public enum PolicyQualifierId
    {
        /// <summary>
        /// Certificate practice statement. Indicates textual (string) 
        /// representation of the qualifier in policy extension
        /// </summary>
        CPS,

        /// <summary>
        /// User notice of the policy qualifier info field.
        /// If this value is present, Qualifier is represented 
        /// as a <see cref="UserNotice"/> object
        /// </summary>
        UserNotice
    }
}
