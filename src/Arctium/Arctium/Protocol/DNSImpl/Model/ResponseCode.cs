using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Model
{
    public enum ResponseCode
    {
        NoErrorCondition = 0,
        
        /// <summary>
        /// The name server was unable to interpret the query
        /// </summary>
        FormatError = 1,

        /// <summary>
        /// the name server was unable to process this query
        /// due to a problem with the name server
        /// </summary>
        ServerFailure = 2,

        /// <summary>
        /// Meaningful only for responsees from an authoritative
        /// name server, this code signifies that the domain
        /// name referenced in query does no exist
        /// </summary>
        NameError = 3,

        /// <summary>
        /// the name server does not support the requested kind of query
        /// </summary>
        NotImplemented = 4,

        /// <summary>
        /// the name server refuses to perform the specified operation
        /// for policy reasons. for example, a name server
        /// may not wish to provide information to the particular requester,
        /// or a name server may not wish to perform a particular operation (e.g., zone
        /// transfer) for particular data.
        /// </summary>
        Refused = 5
    }
}
