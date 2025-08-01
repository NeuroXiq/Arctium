using Arctium.Shared.Other;

namespace Arctium.Protocol.Tls13.Extensions
{
    /// <summary>
    /// Configuration of RFC8446 'CertificateAuthoritiesExtension' extension on server side
    /// </summary>
    public class ExtensionServerConfigCertificateAuthorities
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
        public ExtensionServerConfigCertificateAuthorities(byte[][] authorities)
        {
            Validation.NotEmpty(authorities, nameof(authorities));
            foreach (var auth in authorities)
                Validation.NotEmpty(auth, nameof(authorities), "All entries in authorities must not be empty by specificate. Remove empty entires");

            Authorities = authorities;
        }
    }
}
