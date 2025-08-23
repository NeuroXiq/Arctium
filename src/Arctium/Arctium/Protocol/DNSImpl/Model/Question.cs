using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Model
{
    public class Question
    {
        public string QName;
        public QType QType;
        public QClass QClass;
    }
}
