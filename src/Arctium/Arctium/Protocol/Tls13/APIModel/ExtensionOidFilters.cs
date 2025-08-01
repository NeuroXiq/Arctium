using Arctium.Shared.Other;
using System.Linq;

namespace Arctium.Protocol.Tls13.APIModel
{
    public class ExtensionOidFilters : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.OidFilters;

        public class OidFilter
        {
            public byte[] CertificateExtensionOid { get; private set; }
            public byte[] CertificateExtensionValues { get; private set; }

            public OidFilter(byte[] certificateExtensionOid, byte[] certificateExtensionValues)
            {
                CertificateExtensionOid = certificateExtensionOid;
                CertificateExtensionValues = certificateExtensionValues;
            }

        }

        public OidFilter[] Filters { get; private set; }

        internal ExtensionOidFilters(OidFilter[] filters)
        {
            Validation.NotNull(filters, nameof(filters));
            Filters = filters;
        }
    }
}
