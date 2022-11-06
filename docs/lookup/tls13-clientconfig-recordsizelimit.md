```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 * TLS 1.3 - Client - Record size limit
 * 
 * How to configure Record Size Limit
 * 
 */


using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using System.Net.Sockets;

namespace ConsoleAppTest
{

    internal class MainProgram
    {
        static void Main()
        {
            var context = Tls13ClientContext.DefaultUnsafe();

            // Configuration for Record Size Limit
            // If server supports then records will be of length 1000
            // If server does not support then default config is used
            int maxRecordLen = 1000;
            context.Config.ConfigueExtensionRecordSizeLimit(maxRecordLen);

            var client = new Tls13Client(context);
            var networkStream = Tls13Resources.NetworkStreamToExampleServer();

            var stream = client.Connect(networkStream, out var info);

            var result = info.ExtensionRecordSizeLimit.HasValue ?
                info.ExtensionRecordSizeLimit.Value.ToString() :
                "server not support";

            Console.WriteLine("Record size limit result: {0}", result);
            
            /* In this case server not support this, so default used.
             * If server supports then value will not be null
             * [OUTPUT]
             * Record size limit result: server not support
             * 
             * 
             */
        }
    }
}

```