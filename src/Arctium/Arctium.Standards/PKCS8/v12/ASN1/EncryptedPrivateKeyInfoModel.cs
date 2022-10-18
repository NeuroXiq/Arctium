using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Standards.X509.Model;

namespace Arctium.Standards.PKCS8.v12.ASN1
{
    internal class EncryptedPrivateKeyInfoModel
    {
        public AlgorithmIdentifierModel EncryptionAlgorithmIdentifier;
        public OctetString EncryptedData;
    }
}
