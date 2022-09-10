using Arctium.Cryptography.FileFormats.Exceptions;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace Arctium.Standards.FileFormat.PEM
{
    public class PemFile
    {
        /// <summary>
        /// Begin label of the PEM file
        /// </summary>
        public string BeginLabel { get; private set; }

        /// <summary>
        /// End label of the PEM file
        /// </summary>
        public string EndLabel { get; private set; }

        /// <summary>
        /// Decoded base64 binary data of the PEM file
        /// </summary>
        public byte[] DecodedData { get; private set; }

        public PemFile(string beginLabel, string endLabel, byte[] decodedData)
        {
            BeginLabel = beginLabel;
            EndLabel = endLabel;
            DecodedData = decodedData;
        }

        /// <summary>
        /// Creates <see cref="PemFile"/> object from file
        /// </summary>
        /// <param name="fileName">Path to pem file</param>
        /// <exception cref="InvalidFileFormatException">Throws if file have an incorrect format</exception>
        /// <returns><see cref="PemFile"/> instance from the parsed file</returns>
        public static PemFile FromFile(string fileName)
        {
            string file = File.ReadAllText(fileName);
            file = file.TrimEnd('\r', '\n');

            return FromString(file);
        }

        public static PemFile FromString(string content)
        {
            ByteBuffer buffer = new ByteBuffer();

            string[] lines = content.Split("\r\n");
            if (lines.Length < 3) Throw("Invalid file format. Minimum lines count is 3");

            string beginLabel = GetLabel(lines[0], "BEGIN");
            string endLabel = GetLabel(lines[lines.Length - 1], "END");

            int b64len = (lines.Length - 3) * 64 + lines[lines.Length - 2].Length;

            if (b64len % 4 != 0) Throw("Invalid base64-encoded data length");

            for (int i = 1; i < lines.Length - 1; i++)
            {
                try
                {
                    byte[] decodedLine = Convert.FromBase64String(lines[i]);
                    buffer.Append(decodedLine);
                }
                catch (ArgumentException e)
                {
                    Throw("Invalid Base64-encoded line: " + i);
                }
            }

            byte[] decodedData = MemCpy.CopyToNewArray(buffer.Buffer, 0, buffer.DataLength);

            return new PemFile(beginLabel, endLabel, decodedData);
        }

        private static string GetLabel(string line, string blockName)
        {


            if (!(line.StartsWith($"-----{blockName} ") ||
                line.EndsWith("-----")))
            {
                Throw("Invalid line, expected '-----'");
            }

            int subStart = blockName.Length + 5 + 1;
            int subLength = line.Length - blockName.Length - 5 - 5 -1;

            string label = line.Substring(subStart, subLength);

            return label;
        }

        private static void Throw(string msg)
        {
            throw new InvalidFileFormatException($"File is not in correct PEM format: {msg}");
        }

        public void Save(string fileName) { throw new NotSupportedException(); }

    }
}

/*const string regionDelimiter = "-----";
        const string beginString = "-----BEGIN";
        const string endString = "-----END";
        const int minLength = 31;
        const string pemException = "";*/

//public static PemFile FromFile(string fileName)
//{
//    string file = File.ReadAllText(fileName);
//    if (file.Length < 31) Throw("Minimum length not reached");

//    int startIndex = file.IndexOf(beginString);
//    int startClose = file.IndexOf(regionDelimiter, startIndex + 5);


//    if (startIndex < 0) Throw("Begin Not found");
//    if (startClose < 0) Throw("Begin closing tag not found");


//    int endIndex = file.IndexOf(endString, startClose + 5);
//    int endClose = file.IndexOf(regionDelimiter, endIndex + 5);

//    if (endIndex < 0) Throw("End not found");
//    if(endClose < 0) Throw("End closing not found");

//    //int endExpected = file.Length


//}