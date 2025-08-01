using Arctium.Protocol.QUICv1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.QUICv1Impl
{
    internal class QuicInternalException : QuicException
    {
        public QuicInternalException(string message) : base(message)
        {
        }
    }
}
