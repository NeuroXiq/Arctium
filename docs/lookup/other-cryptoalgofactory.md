```cs
/*
 * Neuroxiq 2022
 * Arctium Project / Code example
 *
 * 
 */


using Arctium.Cryptography.Utils;

namespace ConsoleAppTest
{
    internal class MainProgram
    {
        static void Main()
        {
            // factory method can be used to create hash function
            // like in this example 
            var jh = CryptoAlgoFactory.CreateHashFunction(HashFunctionId.JH_256);
            var sha3 = CryptoAlgoFactory.CreateHashFunction(HashFunctionId.SHA3_512);
            var blake3 = CryptoAlgoFactory.CreateHashFunction(HashFunctionId.BLAKE3);
        }
    }
}

/*
 */
```