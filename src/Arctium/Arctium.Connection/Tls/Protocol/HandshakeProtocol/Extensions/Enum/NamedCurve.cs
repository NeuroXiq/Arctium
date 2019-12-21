namespace Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions
{
    enum NamedCurve : ushort
    {
        //deprecated start 
        Sect163k1 =1,   
        Sect163r1= 2,
        Sect163r2= 3,
        Sect193r1=4,
        Sect193r2= 5,
        Sect233k1= 6,
        Sect233r1=7,
        Sect239k1= 8,
        Sect283k1= 9,
        Sect283r1=10,
        Sect409k1= 11,
        Sect409r1= 12,
        Sect571k1=13,
        Sect571r1= 14,
        Secp160k1= 15,
        Secp160r1=16,
        Secp160r2= 17,
        Secp192k1= 18,
        Secp192r1=19,
        Secp224k1= 20,
        Secp224r1= 21,
        Secp256k1=22,
        // deprecated end
        Secp256r1= 23,
        Secp384r1= 24,
        Secp521r1=25,
        X25519 = 29,
        X448 = 30,
        ffdhe2048 = 256,
        ffdhe3072 = 257,
        ffdhe4096 = 258,
        ffdhe6144 = 259,
        ffdhe8192 = 260,
        ArbitraryExplicitPrimeCurves = 0xFF01,
        ArbitraryExplicitChar2Curves = 0xFF02
    }
}
