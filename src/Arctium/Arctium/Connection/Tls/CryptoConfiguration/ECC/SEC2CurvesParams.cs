using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.CryptoConfiguration.ECC
{
    static class SEC2CurvesParams
    {
        //Dictionary holds key-value pairs of ECDomainParameters (curve params)
        //key of this dictionary is a part of the TLS protocol (keys are NamedCuver enum used by client hello extesnion)
        //current keys should not be a protocol part but this map allows to get specific ECparams directlty from 
        //hello extesnion enum.
        static Dictionary<NamedCurve, ECDomainParameters> extNamedCurveToDomainParamsMap;

        public static ECDomainParameters GetDomainParams(NamedCurve namedCurveType)
        {
            return null;   
        }


        // * * *
        // Constructor and definitions of params,
        // * * *
        //
        // Methods creates specific ECParams and 
        // maybe they will be used to fill different sort of dictionary 
        // with different key.
        // current key is NamedCurve client/server hello extension enum 

        
        //
        // Constructor
        static SEC2CurvesParams()
        {
            extNamedCurveToDomainParamsMap = new Dictionary<NamedCurve, ECDomainParameters>();

            extNamedCurveToDomainParamsMap[NamedCurve.Secp256r1] = CreateSecp256r1();
            extNamedCurveToDomainParamsMap[NamedCurve.Secp384r1] = CreateSecp384r1();
            extNamedCurveToDomainParamsMap[NamedCurve.Secp521r1] = CreateSecp521r1();
        }

        //
        // Methods creating named elliptic curve new ECDomainParams
        // Copy-paste from secg.org/sec2-v2.pdf
        // 

        
        static byte[] ToBytes(string hexString)
        {
            // compute length of byte array

            int doubleLen = 0;
            
            // compute length of the result bytes array,
            // ignore white spaces in calculations

            foreach (char c in hexString) if (c != ' ') doubleLen++;

            byte[] result = new byte[doubleLen / 2];
            int indexInResult = 0;

            //change hex string to byte array
            for (int i = 0; i < hexString.Length; i++)
            {
                if (hexString[i] == ' ') continue;

                //assumes that bytes always are in pairs 
                byte convertedToByte = byte.Parse(hexString.Substring(i,2), System.Globalization.NumberStyles.HexNumber);

                result[indexInResult] = convertedToByte;

                indexInResult++;
                i++;
            }

            return result;
        }
        

        static ECDomainParameters CreateSecp256r1()
        {
            byte[] p = ToBytes("FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFFFFFFFFFF");
            byte[] a = ToBytes("FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFFFFFFFFFC");
            byte[] b = ToBytes("5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E27D2604B");

            byte[] gx = ToBytes("6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0F4A13945 D898C296");
            byte[] gy = ToBytes("4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE33576B315ECE CBB64068 37BF51F5");

            byte[] n = ToBytes("FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2FC632551");
            byte[] h = new byte[] { 1 };

            ECDomainParameters ecParams = new ECDomainParameters(p,a,b,gx,gy,n,h);

            return ecParams;
        }

        static ECDomainParameters CreateSecp384r1()
        {
            byte[] p = ToBytes("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFFFFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFF");
            byte[] a = ToBytes("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFFFFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFC");
            byte[] b = ToBytes("B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF");
            byte[] gx = ToBytes("AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B9859F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7");
            byte[] gy = ToBytes("3617DE4A96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C E9DA3113 B5F0B8C00A60B1CE 1D7E819D 7A431D7C 90EA0E5F");
            byte[] n = ToBytes("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7634D81F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52973");
            byte[] h = new byte[] { 1 };

            ECDomainParameters result = new ECDomainParameters(p, a, b, gx, gy, n, h);

            return result;
        }

        static ECDomainParameters CreateSecp521r1()
        {
            byte[] p = ToBytes("01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFF FFFFFFFF");
            byte[] a = ToBytes("01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFF FFFFFFFC");
            byte[] b = ToBytes("0051 953EB961 8E1C9A1F 929A21A0 B68540EE A2DA725B 99B315F3B8B48991 8EF109E1 56193951 EC7E937B 1652C0BD 3BB1BF07 3573DF883D2C34F1 EF451FD4 6B503F00");
            byte[] gx = ToBytes("00C6858E 06B70404 E9CD9E3E CB662395 B4429C64 8139053FB521F828 AF606B4D 3DBAA14B 5E77EFE7 5928FE1D C127A2FF A8DE3348B3C1856A 429BF97E 7E31C2E5 BD66");
            byte[] gy = ToBytes("0118 39296A78 9A3BC004 5C8A5FB42C7D1BD9 98F54449 579B4468 17AFBD17 273E662C 97EE7299 5EF42640C550B901 3FAD0761 353C7086 A272C240 88BE9476 9FD16650");
            byte[] n = ToBytes("01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFA 51868783 BF2F966B 7FCC0148 F709A5D0 3BB5C9B8899C47AE BB6FB71E 91386409");
            byte[] h = new byte[] { 1 };


            ECDomainParameters result = new ECDomainParameters(p, a, b, gx, gy, n, h);

            return result;
        }



    }
}
