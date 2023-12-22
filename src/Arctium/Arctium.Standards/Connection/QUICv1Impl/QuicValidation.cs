using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    internal class QuicValidation
    {
        public static void ThrowDecodeEx(string msg)
        {
            throw new QuicDecodeException(msg);
        }
    }
}
