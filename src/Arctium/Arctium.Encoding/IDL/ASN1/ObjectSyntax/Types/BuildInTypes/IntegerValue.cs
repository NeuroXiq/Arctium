using Arctium.DllGlobalShared.Helpers.Binary;
using System;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class IntegerValue
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
        byte[] binaryValue;
        ulong longValue;

        public IntegerValue(byte[] binaryValue)
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
            }
        }

        public IntegerValue(ulong value) : this(BinConverter.GetBytesBE(value)) { }

        public static implicit operator ulong(IntegerValue value) => value.ToULong();
        public static explicit operator IntegerValue(ulong value) => new IntegerValue(value);

        public static implicit operator uint(IntegerValue value) { checked { return (uint)value.ToULong(); } }
        public static explicit operator IntegerValue(uint value) => new IntegerValue((ulong)value);

        public static implicit operator ushort(IntegerValue value) { checked { return (ushort)value.ToULong(); } }
        public static explicit operator IntegerValue(ushort value) => new IntegerValue((ulong)value);

        public static implicit operator byte(IntegerValue value) { checked { return (byte)value.ToULong(); } }
        public static explicit operator IntegerValue(byte value) => new IntegerValue((ulong)value);

    }
}
