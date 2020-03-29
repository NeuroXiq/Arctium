using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions
{
    /// <summary>
    /// Special extension, not defined in current Arctium implemetation of X509 standard or
    /// specific extension not standardized anywhere
    /// </summary>
    public class UnknownExtension : CertificateExtension
    {
        /// <summary>
        /// Not mapped raw identifier of unknown extension
        /// </summary>
        public ObjectIdentifier Identifier { get; private set; }
        /// <summary>
        /// Extensions value as a raw bytes of ExtnValue 
        /// </summary>
        public byte[] ExtnValue { get; private set; }
        
        /// <summary>
        /// Creates instance of <see cref="UnknownExtension"/>
        /// </summary>
        /// <param name="extValue"></param>
        /// <param name="oid"></param>
        /// <param name="isCritical"></param>
        public UnknownExtension(byte[] extValue, ObjectIdentifier oid, bool isCritical) : base(ExtensionType.Unknown, isCritical)
        {
            ExtnValue = extValue;
            Identifier = oid;
        }
    }
}
