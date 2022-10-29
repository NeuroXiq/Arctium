using Arctium.Shared.Other;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Extensions
{
    /// <summary>
    /// Configuration for 'Oid filters' ( id_filters (RFC 8446) ) extension on server side.
    /// If configures, server will sent this extension in Extesniosn filter in CertfiicateRequest message 
    /// during client authentication
    /// </summary>
    public class ExtensionServerConfigOidFilters
    {
        /// <summary>
        /// Represents single entry with OID value and corresponding CertificateExtensionValue for this OID.
        /// </summary>
        public class OidFilter
        {
            /// <summary>
            /// Represents DER encoded OID value of certificate extension
            /// </summary>
            public byte[] CertificateExtensionOid { get; private set; }

            /// <summary>
            /// Represents DER encoded OID value of certficiate extension value
            /// </summary>
            public byte[] CertificateExtensionValues { get; private set; }

            public OidFilter(byte[] certificateExtensionOid, byte[] certificateExtensionValues)
            {
                CertificateExtensionOid = certificateExtensionOid;
                CertificateExtensionValues = certificateExtensionValues;
            }
        }

        /// <summary>
        /// Configured OID filters with corresponding Values
        /// </summary>
        public OidFilter[] Filters { get; private set; }


        /// <summary>
        /// Creates new instance of configuration with specified oidFitlers.
        /// oidFilters array (can be empty). All OID byte arrays must not be empty by specification
        /// </summary>
        /// <param name="oidFilters">Filters to sent in CertificateRequest message</param>
        public ExtensionServerConfigOidFilters(OidFilter[] oidFilters)
        {
            foreach (var filter in oidFilters)
            {
                string msg = "DER encoded OID must not be empty by TLS specification. Make sure that all OID byte arrays are not empty";

                Validation.NotEmpty(filter.CertificateExtensionOid, nameof(filter.CertificateExtensionOid), msg);
            }

            Filters = oidFilters;
        }
    }
}
