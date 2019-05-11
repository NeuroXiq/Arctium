using System;

namespace Arctium.Connection.Tls.CryptoConfiguration
{
    public static class CryptoConst
    {
        public const int Tls11MasterSecretLength = 48;


        public static int HashSize(MACAlgorithm macAlgorithm)
        {
            switch (macAlgorithm)
            {
                case MACAlgorithm.NULL: return 0;
                case MACAlgorithm.MD5: return 128;
                case MACAlgorithm.SHA1: return 160;
                default: throw new NotImplementedException("Hash nof found internal error");
            }
        }
    }
}
