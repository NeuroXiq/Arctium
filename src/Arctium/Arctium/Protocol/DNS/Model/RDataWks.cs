using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    /// </summary>
    public class RDataWKS
    {
        public uint Address;
        public byte Protocol;
        /// <summary>
        /// https://datatracker.ietf.org/doc/html/rfc1010
        /// </summary>
        public byte[] Bitmap;
    }
}
