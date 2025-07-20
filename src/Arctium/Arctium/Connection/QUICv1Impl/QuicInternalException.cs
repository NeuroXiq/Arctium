using Arctium.Standards.Connection.QUICv1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    internal class QuicInternalException : QuicException
    {
        public QuicInternalException(string message) : base(message)
        {
        }
    }
}
