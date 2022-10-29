namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
{
    internal class OidFiltersExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.OidFilters;

        public class OidFilter
        {
            public byte[] CertificateExtensionOid { get; private set; }
            public byte[] CertificateExtensionValues { get; private set; }

            public OidFilter(byte[] certficateExtensionOid, byte[] certExtValues)
            {
                CertificateExtensionOid = certficateExtensionOid;
                CertificateExtensionValues = certExtValues;
            }
        }

        public OidFilter[] Filters { get; private set; }

        public OidFiltersExtension(OidFilter[] filters)
        {
            Filters = filters;
        }
    }
}
