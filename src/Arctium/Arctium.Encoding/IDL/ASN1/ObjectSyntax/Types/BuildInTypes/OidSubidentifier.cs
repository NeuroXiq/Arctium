using Arctium.DllGlobalShared.Helpers.Binary;
using System;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct OidSubidentifier
    {
        public byte[] SubidentifierValue;

        public ulong Number
        {
            get
            {
                if (!fitInLong) throw new InvalidOperationException("Cannot represent current value of the OidSubidentifier because it not fit in ulong");
                return longValue;
            }
        }

        private bool fitInLong;
        private ulong longValue;

        public OidSubidentifier(byte[] bitString)
        {
            if (bitString.Length < 9)
            {
                fitInLong = true;
                longValue = BinConverter.ToULongBE(bitString, 0, bitString.Length);
            }
            else
            {
                fitInLong = false;
                longValue = ulong.MaxValue;
            }

            SubidentifierValue = bitString;
        }
    }
}
