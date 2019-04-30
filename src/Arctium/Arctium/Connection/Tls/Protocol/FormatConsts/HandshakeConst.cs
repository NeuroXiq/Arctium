namespace Arctium.Connection.Tls.Protocol.FormatConsts
{
    static class HandshakeConst
    {
        public const int LengthOffset = 1;
        public const int HeaderLength = 4;
        public const int BodyOffset = 4;

        public const int ClientKeyExDecryptedRsaLength = 48;
        public const int ClientKeyExDecrytedRsaRandomLength = 46;
    }
}
