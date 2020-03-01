using Arctium.DllGlobalShared.Helpers.Binary;
using System;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class IntegerValue
    {
        public byte[] BinaryValue {
            get { return binaryValue; }
            set
            {
                binaryValue = value ?? throw new ArgumentException("binaryValue cannot be null");

                if (binaryValue.Length < 9)
                {
                    fitInLong = true;
                    longValue = (long)BinConverter.ToULongBE(value, 0, binaryValue.Length);
                }
                else
                {
                    fitInLong = false;
                }
            }
        }

        public long LongValue
        {
            get
            {
                if (!fitInLong) throw new InvalidOperationException(
                    "Cannot convert current integer value to ulong type " + 
                    "becaues its do not fit in 8-byte structure");
                return longValue;
            }
            set
            {
                binaryValue = BinConverter.GetULtoBEMSTrim((ulong)value);
                fitInLong = true;
                longValue = value;
            }
        }

        bool fitInLong;
        byte[] binaryValue;
        long longValue;

        public IntegerValue(byte[] binaryValue)
        {
            BinaryValue = binaryValue;
        }
    }
}
