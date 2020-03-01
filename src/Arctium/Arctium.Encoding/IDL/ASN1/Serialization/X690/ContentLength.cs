using Arctium.DllGlobalShared.Helpers.Binary;
using System;

namespace Arctium.Encoding.IDL.ASN1.Serialization.X690
{
    public struct ContentLength
    {
        public byte[] FullValue;
        public LengthForm Form;
        public long Length
        {
            get
            {
                if (!fitInLong)
                    throw new InvalidOperationException("Cannot get length value as a 'long' type because it exceed 64-bit integer");
                if (!IsDefinite)
                    throw new InvalidOperationException("Cannot get length as a 'long' type becaues current length value is indefinite");

                return longValue;
            }
        }

        public bool IsDefinite { get { return Form != LengthForm.Indefinite; } }

        private bool fitInLong;
        private long longValue;

        public ContentLength(long value)
        {
            if (value < 0) throw new ArgumentException("length value cannot be negative");

            if (value < 127)
            {
                Form = LengthForm.DefiniteShort;
            }
            else
            {
                Form = LengthForm.DefiniteLong;
            }

            fitInLong = true;
            longValue = value;
            FullValue = BinConverter.GetULtoBEMSTrim((ulong)value);
        }

        public static ContentLength Indefinite
        {
            get
            {
                return CreateIndefinite();
            }
        }

        private static ContentLength CreateIndefinite()
        {
            ContentLength length = new ContentLength();

            length.fitInLong = false;
            length.FullValue = null;
            length.Form = LengthForm.Indefinite;
            length.longValue = -1;

            return length;
        }
    }
}
