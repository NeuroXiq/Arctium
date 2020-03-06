using System;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    /// <summary>
    /// Bit string value used by <see cref="BitString"/> ASN.1 Type object representation.
    /// </summary>
    public struct BitStringValue
    {
        /// <summary>
        /// Contains bit string data where the most significant bit of the <br/>
        /// first byte is first bit in the bit string
        /// </summary>
        public byte[] Value;
        
        /// <summary>
        /// Lenth in bits of the <see cref="Value"/>
        /// </summary>
        public long Length;

        /// <summary>
        /// Creates new instance of the <see cref="BitStringValue"/>
        /// </summary>
        /// <param name="value">Value of the bit string</param>
        /// <param name="length">Bit count in <paramref name="value"/></param>
        public BitStringValue(byte[] value, long length)
        {
            ThrowIfInvalid(value, length);
            Value = value;
            Length = length;
        }

        private static void ThrowIfInvalid(byte[] value, long length)
        {
            if (value == null) throw new ArgumentNullException("value");
            if (length < 0) throw new ArgumentException("length cannot be negative");
            if (length > value.Length * 8) throw new ArgumentException("length exceed capacity of the 'value' parameter");

        }
    }
}
