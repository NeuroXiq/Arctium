using Arctium.Shared.Helpers.Binary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Tests.Cryptography.Ciphers
{
    public class AEADTest
    {
        public int Count;
        public byte[] Key;
        public byte[] IV;
        public byte[] PT;
        public byte[] AAD;
        public byte[] CT;
        public byte[] Tag;
        public bool ExpectedDecryptionFail;

        public static AEADTest CreateEncrypt(string key, string iv, string aad, string pt,  string ct, string tag)
        {
            var t = new AEADTest();

            t.Key = BinConverter.FromString(key);
            t.IV = BinConverter.FromString(iv);
            t.AAD = BinConverter.FromString(aad);
            t.PT = BinConverter.FromString(pt);
            t.CT = BinConverter.FromString(ct);
            t.Tag = BinConverter.FromString(tag);

            return t;
        }
    }
}
