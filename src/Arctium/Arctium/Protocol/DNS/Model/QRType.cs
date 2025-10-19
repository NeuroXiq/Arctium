using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    /// <summary>
    /// one bit
    /// </summary>
    public enum QRType : byte
    {
        Query = 0,
        Response= 1,
    }
}
