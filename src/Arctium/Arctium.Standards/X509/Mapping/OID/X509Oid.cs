using System;
using System.Collections.Generic;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Shared.Mappings.OID;
using Arctium.Standards.X509.X509Cert.Algorithms;
using static Arctium.Standards.ASN1.Standards.X509.Mapping.OID.X509CommonOidsBuilder;

namespace Arctium.Standards.X509.Mapping.OID
{
    public static class X509Oid
    {
        static Dictionary<Type, object> allMappings = new Dictionary<Type, object>();

        static X509Oid()
        {
            Init();
        }

        public static T Get<T>(ObjectIdentifier oid) where T: struct
        {
            var type = typeof(T);

            if (!allMappings.ContainsKey(type))
            {
                string msg = string.Format(
                    "Current type T ('{0}') is not defined in mapping (or not supported)",
                    type.Name);
                throw new ArgumentException(msg);
            }

            var typedDic = allMappings[type] as EnumToOidMap<T>;

            return typedDic[oid];
        }

        private static void Init()
        {
            allMappings.Add(typeof(NamedCurve), NamedCurves());
            allMappings.Add(typeof(SignatureAlgorithmType), CreateSignatureAlgorithmType());
        }

        static ObjectIdentifier ecdsa(ulong last) => new ObjectIdentifier(1, 2, 840, 10045, 4, 3, last);

        private static EnumToOidMap<SignatureAlgorithmType> CreateSignatureAlgorithmType()
        {
            EnumToOidMap<SignatureAlgorithmType> map = new EnumToOidMap<SignatureAlgorithmType>(nameof(SignatureAlgorithmType));

            map[SignatureAlgorithmType.SHA1WithRSAEncryption] = new ObjectIdentifier(1, 2, 840, 113549, 1, 1, 5);
            map[SignatureAlgorithmType.MD2WithRSAEncryption] = pkcs1(2);
            map[SignatureAlgorithmType.DSAWithSha1] = pkcs1(3);
            map[SignatureAlgorithmType.ECDSAWithSHA1] = pkcs1(1);

            map[SignatureAlgorithmType.SHA224WithRSAEncryption] = pkcs1(14);
            map[SignatureAlgorithmType.SHA256WithRSAEncryption] = pkcs1(11);
            map[SignatureAlgorithmType.SHA384WithRSAEncryption] = pkcs1(12);
            map[SignatureAlgorithmType.SHA512WithRSAEncryption] = pkcs1(13);
            map[SignatureAlgorithmType.ECDSAWithSHA224] = ecdsa(1);
            map[SignatureAlgorithmType.ECDSAWithSHA256] = ecdsa(2);
            map[SignatureAlgorithmType.ECDSAWithSHA384] = ecdsa(3);
            map[SignatureAlgorithmType.ECDSAWithSHA512] = ecdsa(4);

            return map;
        }

        static ObjectIdentifier cTwoCurve(ulong last) => new ObjectIdentifier(1,2,840,10045,3,0, last);
        static ObjectIdentifier primeCurve(ulong last) => new ObjectIdentifier(1, 2, 840, 10045, 3, 1, last);
        static ObjectIdentifier rfc5480(ulong last) => new ObjectIdentifier(1,3,132,0,last);

        private static EnumToOidMap<NamedCurve> NamedCurves()
        {
            // var map = new DoubleDictionary<NamedCurve, ObjectIdentifier>();
            var map = new EnumToOidMap<NamedCurve>("NamedCurve");

            map[NamedCurve.c2pnb163v1] = cTwoCurve(1);
            map[NamedCurve.c2pnb163v2] = cTwoCurve(2);
            map[NamedCurve.c2pnb163v3] = cTwoCurve(3);
            map[NamedCurve.c2pnb176w1] = cTwoCurve(4);
            map[NamedCurve.c2tnb191v1] = cTwoCurve(5);
            map[NamedCurve.c2tnb191v2] = cTwoCurve(6);
            map[NamedCurve.c2tnb191v3] = cTwoCurve(7);
            map[NamedCurve.c2onb191v4] = cTwoCurve(8);
            map[NamedCurve.c2onb191v5] = cTwoCurve(9);
            map[NamedCurve.c2pnb208w1] = cTwoCurve(10);
            map[NamedCurve.c2tnb239v1] = cTwoCurve(11);
            map[NamedCurve.c2tnb239v2] = cTwoCurve(12);
            map[NamedCurve.c2tnb239v3] = cTwoCurve(13);
            map[NamedCurve.c2onb239v4] = cTwoCurve(14);
            map[NamedCurve.c2onb239v5] = cTwoCurve(15);
            map[NamedCurve.c2pnb272w1] = cTwoCurve(16);
            map[NamedCurve.c2pnb304w1] = cTwoCurve(17);
            map[NamedCurve.c2tnb359v1] = cTwoCurve(18);
            map[NamedCurve.c2pnb368w1] = cTwoCurve(19);
            map[NamedCurve.c2tnb431r1] = cTwoCurve(20);

            map[NamedCurve.secp192r1] = new ObjectIdentifier(1, 2, 840, 10045, 3, 1, 1);
            map[NamedCurve.secp256r1] = new ObjectIdentifier(1, 2, 840, 10045, 3, 1, 7);
            map[NamedCurve.sect163k1] = rfc5480(1);
            map[NamedCurve.sect163r2] = rfc5480(15);
            map[NamedCurve.secp224r1] = rfc5480(33);   
            map[NamedCurve.sect233k1] = rfc5480(26);
            map[NamedCurve.sect233r1] = rfc5480(27);
            map[NamedCurve.sect283k1] = rfc5480(16);
            map[NamedCurve.sect283r1] = rfc5480(17);
            map[NamedCurve.secp384r1] = rfc5480(34);
            map[NamedCurve.sect409k1] = rfc5480(36);
            map[NamedCurve.sect409r1] = rfc5480(37);
            map[NamedCurve.secp521r1] = rfc5480(35);
            map[NamedCurve.sect571k1] = rfc5480(38);
            map[NamedCurve.sect571r1] = rfc5480(39);            

            map[NamedCurve.prime192v1] = primeCurve(1);
            map[NamedCurve.prime192v2] = primeCurve(2);
            map[NamedCurve.prime192v3] = primeCurve(3);
            map[NamedCurve.prime239v1] = primeCurve(4);
            map[NamedCurve.prime239v2] = primeCurve(5);
            map[NamedCurve.prime239v3] = primeCurve(6);
            map[NamedCurve.prime256v1] = primeCurve(7);

            return map;
        }
    }
}