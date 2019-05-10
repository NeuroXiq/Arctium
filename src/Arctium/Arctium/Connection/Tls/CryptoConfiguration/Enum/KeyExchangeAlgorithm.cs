namespace Arctium.Connection.Tls.CryptoConfiguration
{
    public enum KeyExchangeAlgorithm
    {
        RSA,
        DHE_DSS,
        DHE_RSA,
        DH_DSS,
        DH_RSA,
        ECDH_RSA,
        ECDHE_RSA,
        ECDH_ECDSA,
        ECDHE_ECDSA,
        PSK,
        PSK_RSA,
        DHE_PSK,
        ECDHE_PSK,
        SRP,
        SRP_DSS,
        SRP_RSA,
        Kerberos,
        DH_ANON,
        ECDH_ANON
    }
}
