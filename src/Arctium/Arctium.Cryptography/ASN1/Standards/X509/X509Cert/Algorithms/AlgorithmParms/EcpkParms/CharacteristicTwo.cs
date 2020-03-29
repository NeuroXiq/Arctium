using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert
{
    /// <summary>
    /// Represents Characteristic two parameters for <see cref="ECParameters"/> FieldId.Parameters field.
    /// </summary>
    public struct CharacteristicTwo
    {
        public enum BasisType
        {
            GnBasis,
            TpBasis,
            PpBasis,
        };

        public byte[] M;
        public BasisType Basis;
        
        /// <summary>
        /// defined by Basis
        /// </summary>
        object parameters;

        public T GetParameters<T>()
        {
            switch (Basis)
            {
                case BasisType.GnBasis:
                    return default(T);
                case BasisType.TpBasis:
                    if (typeof(T) == typeof(byte[])) return (T)parameters;
                    else throw new Exception("incalid op");
                case BasisType.PpBasis:
                    if (typeof(T) == typeof(Pentanomial)) return (T)parameters;
                    else throw new Exception("incalid op, expected 'Pentanomial'");
                default:
                    throw new Exception("nor recognized. expected null/pentanomial/byte[] types");
            }
        }
    }
}
