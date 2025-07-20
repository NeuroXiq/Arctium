using Arctium.Shared.Other;
using Arctium.Standards.X509.X509Cert.Algorithms;

namespace Arctium.Standards.PKCS8.v12
{
    public class PrivateKeyInfo
    {
        public long Version { get; private set; }
        public PublicKeyAlgorithmIdentifier PrivateKeyAlgorithmIdentifier { get; private set; }
        public PrivateKey PrivateKey { get; private set; }
        public object[] Attributes_NotSupported { get { Validation.NotSupported(); return null; } }

        public PrivateKeyInfo(long version, PublicKeyAlgorithmIdentifier privateKeyAlgId, PrivateKey privateKey)
        {
            Version = version;
            PrivateKeyAlgorithmIdentifier = privateKeyAlgId;
            PrivateKey = privateKey;
        }
    }
}
