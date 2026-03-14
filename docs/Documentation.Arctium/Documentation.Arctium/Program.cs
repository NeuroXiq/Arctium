using Documentation.Arctium.Protocol;

namespace Documentation.Arctium
{
    class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("=============================================");
            Console.WriteLine("Arctium - Examples");
            Console.WriteLine("=============================================");

            // comment/uncomment examples in specific files to run it

            AllExamples();
        }


        static void AllExamples()
        {
            ExamplesDnsClient.Startup();
            ExamplesDnsServer.Startup();
        }
    }
}