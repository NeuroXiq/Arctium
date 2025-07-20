using Arctium.Standards.Connection.QUICv1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    class QuicDecodeException : QuicException
    {
        public QuicDecodeException(string message) : base(message)
        {
        }
    }
}
