using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct OctetString
    {
        byte[] value;
        public OctetString(byte[] binaryValue)
        {
            value = binaryValue;
        }

        public byte this[long index] { get { return value[index]; } set { this.value[index] = value; } }
    }
}
