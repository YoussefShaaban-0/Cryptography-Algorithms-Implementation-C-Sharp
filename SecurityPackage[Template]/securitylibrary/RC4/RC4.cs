using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {

            //check hexa
            var check = false;
            if (plainText[0] == '0'&& plainText[1] == 'x' && key[0] == '0' && key[1] == 'x') {
                plainText = HextoString(plainText);
                key = HextoString(key);
                check= true;
            }
            char[] k = new char[key.Length];
            for (int i = 0; i < k.Length; i++)
            {
                k[i] = key[i];
            }
            int[] s = new int[256];
            for (int i = 0; i < 256; i++)
            {
                s[i] = i;
            }
            int j = 0;
            for (int i = 0; i < 256; i++)
            {

                j = (j + s[i] + k[i % k.Length]) % 256;
                var temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }

            int x = 0;
            j = 0;
            char[] cipherText = new char[plainText.Length];
            string res = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                //update values
                x = (x + 1) % 256;
                j = (j + s[x]) % 256;
                //swap
                var temp = s[x];
                s[x] = s[j];
                s[j] = temp;
                //xor
                cipherText[i] = (char)(plainText[i] ^ s[(s[x] + s[j]) % 256]);
                res +=cipherText[i];
            }
            if (check)
            {
                res = StringToHexa(res);
                
            }
            return (res);


        }
        public static string HextoString(string hexa)
        {
            string tmp = "", X = "";
            hexa += '1';

            for (int i = 2; i < hexa.Length; i++)
            {
                if (i % 2 == 0 && tmp.Length == 2)
                {
                    int a = 0, b = 0;
                    if (tmp[0] >= '0' && tmp[0] <= '9')
                        a = tmp[0] - '0';

                    else if (tmp[0] >= 'a' && tmp[0] <= 'f')
                        a = tmp[0] - 'a' + 10;

                    if (tmp[1] >= '0' && tmp[1] <= '9')
                        b = tmp[1] - '0';

                    else if (tmp[1] >= 'a' && tmp[1] <= 'f')
                        b = tmp[1] - 'a' + 10;


                    X += (char)((16 * a) + b);
                    tmp = "";
                }
                tmp += hexa[i];
            }
            return X;
        }
        public static string StringToHexa(string inputString)
        {

            string c = inputString;

            string hexa = "0x";
            for (int i = 0; i < c.Length; i++)
            {
                int bas = c[i] / 16;
                int v = c[i] % 16;

                if ((bas >= 0 && bas <= 9) && (v >= 0 && v <= 9))
                {
                    bas += '0';
                    v += '0';
                }


                else if ((bas >= 10 && bas <= 15) && (v >= 10 && v <= 15))
                {
                    bas = 'a' + (bas - 10);
                    v = 'a' + (v - 10);
                }
                
                hexa += (char)(bas); hexa += (char)(v);
            }
            return (hexa);

        }
    }
}
