using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Standards.Connection.Tls.Tls13.API.APIModel
{
    /// <summary>
    /// Maps original 'Model' class to its APIModel equivalent
    /// </summary>
    internal class APIModelMapper
    {
        public static IList<Extension> MapExtensions(IEnumerable<Model.Extensions.Extension> internalExtensions)
        {
            return internalExtensions.Select(MapExtension).ToList();
        }

        public static APIModel.Extension MapExtension(Tls13.Model.Extensions.Extension internalExtension)
        {
            if (internalExtension.ExtensionType == Model.ExtensionType.CertificateAuthorities)
            {
                var internalCertAuths = (Model.Extensions.CertificateAuthoritiesExtension)internalExtension;

                var copied = internalCertAuths.Authorities.Select(byteArray => (byte[])byteArray.Clone()).ToArray();

                return new ExtensionCertificateAuthorities(copied);
            }

            if (internalExtension.ExtensionType == Model.ExtensionType.OidFilters)
            {
                var oidFilters = internalExtension as Model.Extensions.OidFiltersExtension;

                var filters = oidFilters.Filters.Select(f =>
                    new ExtensionOidFilters.OidFilter(
                        (byte[])f.CertificateExtensionOid.Clone(),
                        (byte[])f.CertificateExtensionValues.Clone()))
                    .ToArray();
                
                return new ExtensionOidFilters(filters);
            }

            if (internalExtension.ExtensionType == Model.ExtensionType.SignatureAlgorithms)
            {
                var sigAlgosExt = internalExtension as Model.Extensions.SignatureSchemeListExtension;

                var mapped = sigAlgosExt.Schemes.Select(s => (SignatureScheme)s).ToArray();

                return new ExtensionSignatureSchemeList(mapped);
            }

            return new UnknownExtension();
        }
    }
}
