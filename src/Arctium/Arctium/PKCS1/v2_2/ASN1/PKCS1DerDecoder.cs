using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using System;

namespace Arctium.Standards.PKCS1.v2_2.ASN1
{
    public class PKCS1DerDecoder
    {
        private DerTypeDecoder derTypeDecoder;

        public PKCS1DerDecoder()
        {
        }

        public RSAPrivateKey DecodeRsaPrivateKey(byte[] derEncodedBytes)
        {
            var deserialized = DerDeserializer.Deserialize(derEncodedBytes, 0);

            derTypeDecoder = new DerTypeDecoder(derEncodedBytes);

            RSAPrivateKeyModel pkModel = DecodeDeserializedRsaPrivateKeyToModel(deserialized);
            RSAPrivateKey rsaPrivateKey = MapModelToObject(pkModel);

            return rsaPrivateKey;
        }

        public RSAPublicKey DecodeRsaPublicKey(byte[] derEncodedBytes)
        {
            var deserialized = DerDeserializer.Deserialize(derEncodedBytes, 0);

            derTypeDecoder = new DerTypeDecoder(derEncodedBytes);

            RSAPublicKeyModel pkModel = DecodeDeserializedRsaPublicKeyToModel(deserialized);
            RSAPublicKey rsaPublicKey = MapModelToObject(pkModel);

            return rsaPublicKey;
        }

        private RSAPublicKey MapModelToObject(RSAPublicKeyModel pkModel)
        {
            return new RSAPublicKey(pkModel.Modulus.BinaryValue, pkModel.PublicExponent.BinaryValue);
        }

        private RSAPublicKeyModel DecodeDeserializedRsaPublicKeyToModel(DerDecoded deserialized)
        {
            return new RSAPublicKeyModel
            {
                Modulus = derTypeDecoder.Integer(deserialized[0]),
                PublicExponent = derTypeDecoder.Integer(deserialized[1])
            };
        }

        private RSAPrivateKey MapModelToObject(RSAPrivateKeyModel pkModel)
        {
            RSAPrivateKey privateKey = new RSAPrivateKey();

            privateKey.Version = (int)pkModel.Version.ToLong();
            privateKey.Modulus = pkModel.Modulus.BinaryValue;
            privateKey.PublicExponent = pkModel.PublicExponent.BinaryValue;
            privateKey.PrivateExponent = pkModel.PrivateExponent.BinaryValue;
            privateKey.Prime1 = pkModel.Prime1.BinaryValue;
            privateKey.Prime2 = pkModel.Prime2.BinaryValue;
            privateKey.Exponent1 = pkModel.Exponent1.BinaryValue;
            privateKey.Exponent2 = pkModel.Exponent2.BinaryValue;
            privateKey.Coefficient = pkModel.Coefficient.BinaryValue;

            if (pkModel.OtherPrimeInfos != null)
            {
                privateKey.OtherPrimeInfos = new OtherPrimeInfo[pkModel.OtherPrimeInfos.Length];

                for (int i = 0; i < pkModel.OtherPrimeInfos.Length; i++)
                {
                    OtherPrimeInfoModel model = pkModel.OtherPrimeInfos[i];
                    OtherPrimeInfo primeInfo = new OtherPrimeInfo();

                    primeInfo.Coefficient = model.Coefficient.BinaryValue;
                    primeInfo.Exponent = model.Exponent.BinaryValue;
                    primeInfo.Prime = model.Prime.BinaryValue;

                    privateKey.OtherPrimeInfos[i] = primeInfo;
                }
            }

            return privateKey;
        }

        private RSAPrivateKeyModel DecodeDeserializedRsaPrivateKeyToModel(DerDecoded decoded)
        {
            RSAPrivateKeyModel model = new RSAPrivateKeyModel();

            model.Version = derTypeDecoder.Integer(decoded[0]);
            model.Modulus = derTypeDecoder.Integer(decoded[1]);
            model.PublicExponent = derTypeDecoder.Integer(decoded[2]);
            model.PrivateExponent = derTypeDecoder.Integer(decoded[3]);
            model.Prime1 = derTypeDecoder.Integer(decoded[4]);
            model.Prime2 = derTypeDecoder.Integer(decoded[5]);
            model.Exponent1 = derTypeDecoder.Integer(decoded[6]);
            model.Exponent2 = derTypeDecoder.Integer(decoded[7]);
            model.Coefficient = derTypeDecoder.Integer(decoded[8]);
            model.OtherPrimeInfos = null;

            int othersPrimeInfoLength = decoded.ConstructedCount > 9 ? (int)decoded[9].ConstructedCount : 0;

            if (othersPrimeInfoLength > 0)
            {
                DerDecoded otherPrimeInfos = decoded[9];
                model.OtherPrimeInfos = new OtherPrimeInfoModel[othersPrimeInfoLength];

                for (int i = 0; i < othersPrimeInfoLength; i++)
                {
                    DerDecoded primeInfo = otherPrimeInfos[i];
                    OtherPrimeInfoModel otherPrime = new OtherPrimeInfoModel();

                    otherPrime.Prime = derTypeDecoder.Integer(primeInfo[0]);
                    otherPrime.Exponent = derTypeDecoder.Integer(primeInfo[1]);
                    otherPrime.Coefficient = derTypeDecoder.Integer(primeInfo[2]);

                    model.OtherPrimeInfos[i] = otherPrime;
                }
            }


            return model;
        }
    }
}
