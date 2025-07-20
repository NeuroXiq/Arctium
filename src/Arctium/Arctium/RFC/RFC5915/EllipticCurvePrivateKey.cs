using Arctium.Standards.ArctiumLibShared;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.RFC.RFC5915
{
    /// <summary>
    /// RFC 5915
    ///  Elliptic Curve Private Key Structure
    /// </summary>
    public class EllipticCurvePrivateKey : IArctiumConvertable<ECPrivateKey>
    {
        public long Version { get; private set; }

        /// <summary>
        /// It is an octet string of length
        /// ceiling(log2(n)/8) (where n is the order of the curve) obtained
        /// from the unsigned integer via the Integer-to-Octet-String-
        /// Primitive(I2OSP) defined in [RFC3447].
        /// </summary>
        public byte[] PrivateKey { get; private set; }

        /// <summary>
        /// Parameters in RFC is 'ECParameters' structure but
        /// only namedcurve is only one possible
        /// option so ignoring underlying CHOICE obj and 
        /// using enum directly
        /// </summary>
        public NamedCurve? Parameters { get; private set; }

        /// <summary>
        /// Optional public key if present, otherwise null
        /// </summary>
        public byte[] PublicKey { get; private set; }

        public EllipticCurvePrivateKey(long version, byte[] privateKey) : this(version, privateKey, null, null)
        { }

        public EllipticCurvePrivateKey(long version, byte[] privateKey, NamedCurve? parameters, byte[] publicKey)
        {
            Version = version;
            PrivateKey = privateKey;
            Parameters = parameters;
            PublicKey = publicKey;
        }

        public ECPrivateKey Convert()
        {
            return new ECPrivateKey(PrivateKey);
        }
    }
}
