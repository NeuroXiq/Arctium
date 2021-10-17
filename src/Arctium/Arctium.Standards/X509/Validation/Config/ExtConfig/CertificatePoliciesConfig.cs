namespace Arctium.Standards.ASN1.Standards.X509.Validation.Config
{
    /// <summary>
    /// Validation configuration for <see cref="CertificatePoliciesExtension"/>
    /// </summary>
    public struct CertificatePoliciesConfig
    {
        /// <summary>
        /// Default: FALSE <br/>
        /// Indicates if size of the ExplicitText filed should not exceed
        /// 200 chars (as spec says). This limit may be <br/>
        /// ignored by issuers of certificates.
        /// </summary>
        public bool ExplicitTextMax200;

        /// <summary>
        /// Default: FALSE <br/>
        /// Profile RECOMMENDS that Policy information should consist only of OID value
        /// without additional data.
        /// </summary>
        public bool PolicyInformationIsOnlyOID;



        public static CertificatePoliciesConfig Default()
        {
            CertificatePoliciesConfig p = new CertificatePoliciesConfig();
            p.ExplicitTextMax200 = false;
            p.PolicyInformationIsOnlyOID = false;

            return p;
        }
    }
}
