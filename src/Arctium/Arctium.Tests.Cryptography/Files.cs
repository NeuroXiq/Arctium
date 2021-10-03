namespace Arctium.Tests.Cryptography
{
    public static class Files
    {
        public const string SkeinTestVectorsDir = "HashFunctions/TestVectors/Skein/";
        public static string JHTestVectorsDirFullPath => GetFullPath("HashFunctions/TestVectors/JH/");

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
