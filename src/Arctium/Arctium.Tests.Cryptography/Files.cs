using System;
using System.Collections.Generic;
using System.Text;

namespace Arctium.Tests.Cryptography
{
    public static class Files
    {
        public const string SkeinTestVectorsDir = "HashFunctions/TestVectors/Skein/";
        static string CryptographyFilesFolder = null;

        public static void SetArctiumFilesPath(string fullPath)
        {
            CryptographyFilesFolder = fullPath + "/" + "Tests/Arctium_Tests_Cryptography/";
        }

        public static string GetFullPath(string fileName)
        {
            return CryptographyFilesFolder + fileName;
        }
    }
}
