using System;
using System.Text;

namespace LikesEvasion
{
    class Evade
    {
        // Convert hex to string
        public static string FromHex(string data)
        {
            String ret = "";
            string[] split = new string[data.Length / 2 + (data.Length % 2 == 0 ? 0 : 1)];
            for (int i = 0; i < split.Length; i++)
            {
                ret = ret + System.Convert.ToChar(System.Convert.ToUInt32("0x00" + data.Substring(i * 2, i * 2 + 2 > data.Length ? 1 : 2), 16)).ToString();
            }

            return ret;
        }
        // Decrypt XOR'd string
        public static string Deflate(string input, string key)
        {
            var kL = key.Length;

            StringBuilder output = new StringBuilder();
            for (int i = 0; i < input.Length; i++)
                output.Append((char)(input[i] ^ key[(i % key.Length)]));
            String result = output.ToString();

            return result;
        }
    }
}
