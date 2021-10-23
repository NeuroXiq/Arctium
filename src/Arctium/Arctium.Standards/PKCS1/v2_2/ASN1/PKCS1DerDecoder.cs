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
            return new RSAPublicKey(TrimLeadingZeroBytes(pkModel.Modulus.BinaryValue), 
                TrimLeadingZeroBytes(pkModel.PublicExponent.BinaryValue));
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

            privateKey.Version = (int)pkModel.Version.ToULong();
            privateKey.Modulus = TrimLeadingZeroBytes(pkModel.Modulus.BinaryValue);
            privateKey.PublicExponent = TrimLeadingZeroBytes(pkModel.PublicExponent.BinaryValue);
            privateKey.PrivateExponent = TrimLeadingZeroBytes(pkModel.PrivateExponent.BinaryValue);
            privateKey.Prime1 = TrimLeadingZeroBytes(pkModel.Prime1.BinaryValue);
            privateKey.Prime2 = TrimLeadingZeroBytes(pkModel.Prime2.BinaryValue);
            privateKey.Exponent1 = TrimLeadingZeroBytes(pkModel.Exponent1.BinaryValue);
            privateKey.Exponent2 = TrimLeadingZeroBytes(pkModel.Exponent2.BinaryValue);
            privateKey.Coefficient = TrimLeadingZeroBytes(pkModel.Coefficient.BinaryValue);

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

        private byte[] TrimLeadingZeroBytes(byte[] array)
        {
            int nonZeroByteIndex = 0;
            while (array[nonZeroByteIndex] == 0 && nonZeroByteIndex < array.Length) nonZeroByteIndex++;

            if (nonZeroByteIndex >= array.Length) throw new ArgumentException("cannot trim leading zeroes because all bytes are zero");

            if (nonZeroByteIndex != 0)
            {
                byte[] newArray = new byte[array.Length - nonZeroByteIndex];

                Buffer.BlockCopy(array, nonZeroByteIndex, newArray, 0, array.Length - nonZeroByteIndex);

                array = newArray;
            }

            return array;
        }
    }
}
