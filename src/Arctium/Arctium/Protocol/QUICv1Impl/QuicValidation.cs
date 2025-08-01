using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.QUICv1Impl
{
    internal class QuicValidation
    {
        public static void ThrowDecodeEx(string msg)
        {
            throw new QuicDecodeException(msg);
        }

        public static void ThrowDecodeEx(bool condition, string msg)
        {
            if (condition) ThrowDecodeEx(msg);
        }
    }
}
