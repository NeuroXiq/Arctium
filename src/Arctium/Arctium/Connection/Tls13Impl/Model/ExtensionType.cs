namespace Arctium.Standards.Connection.Tls13Impl.Model
{
    enum ExtensionType : ushort
    {
        ServerName = 0, /* RFC 6066 */
        MaxFragmentLength = 1, /* RFC 6066 */

        /// <summary>
        /// RFC 6066
        /// </summary>
        StatusRequest = 5, /* RFC 6066 */

        SupportedGroups = 10, /* RFC 8422, 7919 */
        SignatureAlgorithms = 13, /* RFC 8446 */
        UseSrtp = 14, /* RFC 5764 */
        Heartbeat = 15, /* RFC 6520 */
        ApplicationLayerProtocolNegotiation = 16, /* RFC 7301 */
        SignedCertificateTimestamp = 18, /* RFC 6962 */
        ClientCertificateType = 19, /* RFC 7250 */
        ServerCertificateType = 20, /* RFC 7250 */
        Padding = 21, /* RFC 7685 */

        /// <summary>
        /// Request for Comments: 8449
        /// Record Size Limit Extension for TLS
        /// </summary>
        RecordSizeLimit = 28,
        PreSharedKey = 41, /* RFC 8446 */
        EarlyData = 42, /* RFC 8446 */
        SupportedVersions = 43, /* RFC 8446 */
        Cookie = 44, /* RFC 8446 */
        PskKeyExchangeModes = 45, /* RFC 8446 */
        CertificateAuthorities = 47, /* RFC 8446 */
        OidFilters = 48, /* RFC 8446 */
        PostHandshakeAuth = 49, /* RFC 8446 */
        SignatureAlgorithmsCert = 50, /* RFC 8446 */
        KeyShare = 51, /* RFC 8446 */

        QuicTransportParameters = 57, /* RFC 9001 */
    }
}