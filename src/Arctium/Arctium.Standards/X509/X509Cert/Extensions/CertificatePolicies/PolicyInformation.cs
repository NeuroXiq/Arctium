using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.X509.X509Cert.Extensions
{
    public class PolicyInformation
    {
        public static readonly ObjectIdentifier AnyPolicy = new ObjectIdentifier(2, 5, 29, 32, 0);
        public ObjectIdentifier PolicyIdentifier { get; private set; }
        
        /// <summary>
        /// This value can be null <br/>
        /// Represents policy qualifiers as an OPTIONAL parameter in 
        /// PolicyInformation structure.
        /// </summary>
        public PolicyQualifierInfo[] PolicyQualifiers { get; private set; }

        public PolicyInformation(ObjectIdentifier policyIdentifier, PolicyQualifierInfo[] policyQualifiers)
        {
            PolicyIdentifier = policyIdentifier;
            PolicyQualifiers = policyQualifiers;
        }
    }
}
