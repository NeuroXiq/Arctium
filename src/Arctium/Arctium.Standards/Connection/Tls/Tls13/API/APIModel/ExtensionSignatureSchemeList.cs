namespace Arctium.Standards.Connection.Tls.Tls13.API.APIModel
{
    /// <summary>
    /// Represents Signature Algorithms extension (RFC 8446) with signatures values
    /// </summary>
    public class ExtensionSignatureSchemeList : Extension
    {
        /// <summary>
        /// Supported signature values 
        /// </summary>
        public SignatureScheme[] SupportedSignatureAlgorithms { get; private set; }

        public override ExtensionType ExtensionType => ExtensionType.SignatureAlgorithms;

        internal ExtensionSignatureSchemeList(SignatureScheme[] schemes)
        {
            SupportedSignatureAlgorithms = schemes;
        }
    }
}
