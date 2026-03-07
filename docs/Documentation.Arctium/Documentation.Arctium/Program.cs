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

            // select example to run
            ExamplesDnsClient.Startup();

            //
            // AllExamples();
        }


        static void AllExamples()
        {
            //
            // Check example to run
            //

            ExamplesDnsClient.Startup();
        }
    }
}