using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;
using System;

namespace Arctium.Protocol.Tls.Tls12.CryptoConfiguration
{
    public static class CryptoConst
    {
        public const int Tls11MasterSecretLength = 48;


        public static int HashSize(HashAlgorithmType macAlgorithm)
        {
            switch (macAlgorithm)
            {
                case HashAlgorithmType.NULL: return 0;
                case HashAlgorithmType.MD5: return 128;
                case HashAlgorithmType.SHA1: return 160;
                default: throw new NotImplementedException("Hash nof found internal error");
            }
        }
    }
}
