using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    /// <summary>
    /// Variation of the choice type <see cref="EcpkParameters"/> algorithm parameters
    /// </summary>
    public struct ECParameters
    {
        public enum FieldType
        {
            PrimeField,
            CharacteristicTwoField
        }

        public int version;

        /// <summary>
        /// (FieldID)
        /// </summary>
        public FieldType FType;

        private object parameters;

        public BitString ACurveParam;
        public BitString BCurveParam;

        /// <summary>
        /// OPTIONAL
        /// </summary>
        public BitString SeedCurveParam;

        public byte[] FieldElement;
        public byte[] Base;
        public byte[] Order;
        
        /// <summary>
        /// OPTIONAL
        /// </summary>
        public byte[] Cofactor;

        /// <summary>
        /// (FieldID) Parameters
        /// </summary>
        /// <typeparam name="T">Casting parameters: PrimeP, CharacteristicTwo</typeparam>
        /// <returns></returns>
        public T GetFieldParameters<T>()
        {
            switch (FType)
            {
                case FieldType.PrimeField:
                    if (typeof(T) != typeof(byte[])) throw new Exception("expected byte[]");
                    else return (T)parameters;
                case FieldType.CharacteristicTwoField:
                    if (typeof(CharacteristicTwo) != typeof(T)) throw new InvalidCastException("Expected 'characteristicTwo'");
                    return (T)parameters;
                default:
                    throw new Exception("Expected byte[] (for prime) or characteristiTwo types");
            }
        }
    }
}
