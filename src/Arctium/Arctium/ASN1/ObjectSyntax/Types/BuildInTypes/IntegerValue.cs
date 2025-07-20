using Arctium.Shared.Helpers.Binary;
using Arctium.Shared.Other;
using System;

namespace Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes
{
    /// <summary>
    /// Can be positive or negative value
    /// </summary>
    public struct Integer
    {
        public byte[] BinaryValue { get; private set; }

        /// <summary>
        /// Tries to convert to signed long ('long') value if possible. If not possible exception
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException">If not possible to convert (length in bytes is more than 8 bytes)</exception>
        public long ToLong()
        {
            {
                if (!fitInLong) throw new InvalidOperationException(
                    "Cannot convert current integer value to ulong type " +
                    "because it do not fit in 8-byte structure");
                return longValue;
            }
        }

        bool fitInLong;
        long longValue;

        public Integer(byte[] binaryValue)
        {
            BinaryValue = binaryValue;
            if (binaryValue.Length < 9)
            {
                fitInLong = true;
                longValue = ConvertToLong(binaryValue);
            }
            else
            {
                fitInLong = false;
                longValue = long.MinValue;
            }
        }

        /// <summary>
        /// TODO MUST: this doesn't work because can be negative. Convert to negative because is 2's complemnentary
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static long ConvertToLong(byte[] value)
        {
            Validation.ThrowInternal(value.Length > 8);

            long result = 0;
            
            for (int i = 0; i < value.Length; i++)
                result |= (value[value.Length - 1 - i] << (i * 8));

            // if len == 8 so sign byte is set,
            if (value.Length < 8)
            { }

            return result;
        }


        public Integer(ulong value) : this(BinConverter.ToBytesBE(value)) { }

        public static implicit operator ulong(Integer value) => (ulong)value.ToLong();
        public static explicit operator Integer(ulong value) => new Integer(value);

        public static implicit operator uint(Integer value) { checked { return (uint)value.ToLong(); } }
        public static explicit operator Integer(uint value) => new Integer((ulong)value);

        public static implicit operator ushort(Integer value) { checked { return (ushort)value.ToLong(); } }
        public static explicit operator Integer(ushort value) => new Integer((ulong)value);

        public static implicit operator byte(Integer value) { checked { return (byte)value.ToLong(); } }
        public static explicit operator Integer(byte value) => new Integer((ulong)value);

    }
}
