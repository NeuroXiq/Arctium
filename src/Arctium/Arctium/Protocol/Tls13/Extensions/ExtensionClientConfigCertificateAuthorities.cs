using Arctium.Shared.Other;

namespace Arctium.Protocol.Tls13.Extensions
{
    /// <summary>
    /// Configuration of RFC8446 'CertificateAuthoritiesExtension' extension on client side
    /// </summary>
    public class ExtensionClientConfigCertificateAuthorities
    {
        public byte[][] Authorities;

        /// <summary>
        /// Creates new instance with specified authorities as array of byte arrays
        /// (each array must be is DER encoded X501 distinguished name
        /// </summary>
        /// <param name="authorities">DER encoded [X501 - Distinguished name] certificate authorities.
        /// In TLS 1.3 (RFC 8446) specification this array is injected into Extension 
        /// 'CertificateAuthoritiesExtension' into field 
        /// 'DistinguishedName authorities<3..2^16-1>'</param>
        public ExtensionClientConfigCertificateAuthorities(byte[][] authorities)
        {
            Validation.NotEmpty(authorities, nameof(authorities), "list cannot be empty by specification");

            foreach (var b in authorities)
            {
                Validation.NotEmpty(b, nameof(authorities),
                    "one or more byte array in authorities is empty but it cannot be empty by specification. Remove empty arrays");
            }

            Authorities = authorities;
        }
    }
}
