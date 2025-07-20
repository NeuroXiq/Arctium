using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Arctium.Standards.Connection.Tls13.APIModel;
using Arctium.Standards.Connection.Tls13;
using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13.APIModel
{
    /// <summary>
    /// Maps original 'Model' class to its APIModel equivalent
    /// </summary>
    internal class APIModelMapper
    {
        public static IList<Extension> MapExtensions(IEnumerable<Tls13Impl.Model.Extensions.Extension> internalExtensions)
        {
            return internalExtensions.Select(MapExtension).ToList();
        }

        public static Extension MapExtension(Tls13Impl.Model.Extensions.Extension internalExtension)
        {
            if (internalExtension.ExtensionType == Tls13Impl.Model.ExtensionType.CertificateAuthorities)
            {
                var internalCertAuths = (Tls13Impl.Model.Extensions.CertificateAuthoritiesExtension)internalExtension;

                var copied = internalCertAuths.Authorities.Select(byteArray => (byte[])byteArray.Clone()).ToArray();

                return new ExtensionCertificateAuthorities(copied);
            }

            if (internalExtension.ExtensionType == Tls13Impl.Model.ExtensionType.OidFilters)
            {
                var oidFilters = internalExtension as Tls13Impl.Model.Extensions.OidFiltersExtension;

                var filters = oidFilters.Filters.Select(f =>
                    new ExtensionOidFilters.OidFilter(
                        (byte[])f.CertificateExtensionOid.Clone(),
                        (byte[])f.CertificateExtensionValues.Clone()))
                    .ToArray();

                return new ExtensionOidFilters(filters);
            }

            if (internalExtension.ExtensionType == Tls13Impl.Model.ExtensionType.SignatureAlgorithms)
            {
                var sigAlgosExt = internalExtension as Tls13Impl.Model.Extensions.SignatureSchemeListExtension;

                var mapped = sigAlgosExt.Schemes.Select(s => (SignatureScheme)s).ToArray();

                return new ExtensionSignatureSchemeList(mapped);
            }

            return new UnknownExtension();
        }
    }
}
