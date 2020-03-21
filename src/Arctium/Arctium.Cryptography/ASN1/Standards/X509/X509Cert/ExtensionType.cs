namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    public enum ExtensionType
    {
        /// <summary>
        /// This special value indicates, that 
        /// extension is not defined/supported by current implementation.
        /// Therefore class representing this extension do not exists.
        /// </summary>
        Unrecognized,
        AuthorityKeyIdentifier,


        //KeyIdentifier,
        //BasicConstraint,
        //NameConstraint,
        //ExtendedKeyUsage,
        //InhibitAntipolicy,
        //SubjectAlternativeName,
        //KeyUsage,
        //CertificatePolicy,
        //Authority,
        //SubjectKeyIdentifier,
        //Policy
    }
}
