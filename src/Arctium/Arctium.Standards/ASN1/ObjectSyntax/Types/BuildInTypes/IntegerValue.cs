using Arctium.Shared.Helpers.Binary;
using System;

namespace Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct Integer
    {
        public byte[] BinaryValue { get; private set; }

        public ulong ToULong()
        {
            {
                if (!fitInLong) throw new InvalidOperationException(
                    "Cannot convert current integer value to ulong type " +
                    "because it do not fit in 8-byte structure");
                return longValue;
            }
        }

        bool fitInLong;
        ulong longValue;

        public Integer(byte[] binaryValue)
        {
            BinaryValue = binaryValue;
            if (binaryValue.Length < 9)
            {
                fitInLong = true;
                longValue = BinConverter.ToULongBE(binaryValue, 0, binaryValue.Length);
            }
            else
            {
                fitInLong = false;
                longValue = ulong.MaxValue;
            }
        }

        public Integer(ulong value) : this(BinConverter.ToBytesBE(value)) { }

        public static implicit operator ulong(Integer value) => value.ToULong();
        public static explicit operator Integer(ulong value) => new Integer(value);

        public static implicit operator uint(Integer value) { checked { return (uint)value.ToULong(); } }
        public static explicit operator Integer(uint value) => new Integer((ulong)value);

        public static implicit operator ushort(Integer value) { checked { return (ushort)value.ToULong(); } }
        public static explicit operator Integer(ushort value) => new Integer((ulong)value);

        public static implicit operator byte(Integer value) { checked { return (byte)value.ToULong(); } }
        public static explicit operator Integer(byte value) => new Integer((ulong)value);

    }
}
