using Arctium.Shared.Other;

namespace Arctium.Protocol.Tls13.Extensions
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
                string msg = "DER encoded OID must not be empty (at least 1 byte) and max length is 255 - by TLS specification. That all oids filters meet this criterion";
                string msg2 = "DER encoded CertificateExtensionValues length cannot exceed 2^16 -1 ";

                Validation.NumberInRange(filter.CertificateExtensionOid.Length, 1, 255, nameof(filter), msg);
                Validation.NumberInRange(filter.CertificateExtensionValues.Length, 0, ushort.MaxValue, nameof(filter.CertificateExtensionValues), msg2);
            }

            Filters = oidFilters;
        }
    }
}
