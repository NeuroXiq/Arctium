
/*
 * This is a mapper from ObjectIdentifier to AlgorithmIdentifier and vice versa
 * 
 * Maps Oid to enum type and enum to Oid
 * 
 */

using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate;
using static Arctium.DllGlobalShared.Constants.Algorithm;
using Arctium.DllGlobalShared.Helpers.DataStructures;
using System;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Mapping
{
    

    public class AlgorithmMapper
    {
        DoubleDictionary<ObjectIdentifier, SignatureAlgorithm> signatureMap;
        DoubleDictionary<ObjectIdentifier, PublicKeyAlgorithm> publicKeyMap;

        public AlgorithmMapper()
        {
            signatureMap = new DoubleDictionary<ObjectIdentifier, SignatureAlgorithm>();
            publicKeyMap = new DoubleDictionary<ObjectIdentifier, PublicKeyAlgorithm>();

            CreateSignatureMappings();
            CreatePublicKeyMappings();
        }

        public ObjectIdentifier GetOid(SignatureAlgorithm signatureAlgorithm) => signatureMap[signatureAlgorithm];
        public ObjectIdentifier GetOid(PublicKeyAlgorithm publicKeyAlgorithm) => publicKeyMap[publicKeyAlgorithm];
        public PublicKeyAlgorithm GetPublicKeyAlgorithm(ObjectIdentifier oid) => publicKeyMap[oid];
        public SignatureAlgorithm GetSignatureAlgorithm(ObjectIdentifier oid) => signatureMap[oid];

        private void CreatePublicKeyMappings()
        {
            publicKeyMap[PublicKeyAlgorithm.ECPublicKey] = new ObjectIdentifier(1, 2, 840, 10045, 2, 1);

            var x = new ObjectIdentifier(1, 2, 840, 10045, 2, 1).ToString();

        }

        private void CreateSignatureMappings()
        {
            // RSA 

            signatureMap[Md2Rsa] = new SignatureAlgorithm(MD2, RSA);
            signatureMap[Md5Rsa] = new SignatureAlgorithm(MD5, RSA);
            signatureMap[Sha1hRsa] = new SignatureAlgorithm(SHA1, RSA);
            signatureMap[sha256Rsa] = new SignatureAlgorithm(SHA2_256, RSA);

            //DSA
            signatureMap[DsaSha1] = new SignatureAlgorithm(SHA1, DSA);

            //ECDSA
            signatureMap[EcdsaSha1] = new SignatureAlgorithm(SHA1, RSA);

        }



        /*
         * Signature Values
         * */

        // RSA

        static readonly ObjectIdentifier DsaSha1 = new ObjectIdentifier(1, 2, 840, 10040, 4, 3);
        static readonly ObjectIdentifier Md2Rsa = pkcs1(1);
        static readonly ObjectIdentifier Md5Rsa = pkcs1(4);
        static readonly ObjectIdentifier Sha1hRsa = pkcs1(5);
        static readonly ObjectIdentifier sha256Rsa = new ObjectIdentifier(1, 2, 840, 113549, 1, 1, 11);
        // ECDSA

        static readonly ObjectIdentifier EcdsaSha1 = new ObjectIdentifier(1, 2, 840, 10045, 4, 1);


        // Helpers


        static ObjectIdentifier pkcs1(ulong value)
        {
            return new ObjectIdentifier(1, 2, 840, 113549, 1, value);
        }
    }
}
