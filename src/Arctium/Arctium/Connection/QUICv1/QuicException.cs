using Arctium.Shared.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1
{
    internal class QuicException : ArctiumException
    {
        public QuicException(string message) : base(message)
        {
        }
    }
}
