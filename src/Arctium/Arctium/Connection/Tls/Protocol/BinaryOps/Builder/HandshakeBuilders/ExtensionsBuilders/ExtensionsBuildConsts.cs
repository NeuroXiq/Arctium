using Arctium.Connection.Tls.CryptoConfiguration;

namespace Arctium.Connection.Tls.Protocol.BinarOps.HandshakeBuilders.ExtensionsBuilders
{
    static class ExtensionsBuildConsts
    {
        public static SignatureAlgorithm SignatureAlgorithmsHashSignAlgoPair(byte hashAlgoByte, byte signAlgoByte)
        {
            SignatureAlgorithm signAlgo = SignatureAlgorithm.NULL;
            HashAlgorithmType hashAlgo = HashAlgorithmType.NULL;

            switch (signAlgoByte)
            {
                case 1: signAlgo = SignatureAlgorithm.RSA; break;
                case 2: signAlgo = SignatureAlgorithm.DSA; break;
                case 3: signAlgo = SignatureAlgorithm.ECDSA; break;
            }

            switch (hashAlgoByte)
            {
                case 1: hashAlgo = HashAlgorithmType.MD5; break;
                case 2: hashAlgo = HashAlgorithmType.SHA1; break;
                case 3: hashAlgo = HashAlgorithmType.SHA224; break;
                case 4: hashAlgo = HashAlgorithmType.SHA256; break;
                case 5: hashAlgo = HashAlgorithmType.SHA384; break;
                case 6: hashAlgo = HashAlgorithmType.SHA512; break;
            }

            
        }
    }
}
