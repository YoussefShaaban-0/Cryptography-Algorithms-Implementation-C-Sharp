using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {

            // if (key > 26)
            //    key = key % 26;
            //else 
            if (key < 0)
                key = (key) + 26;

            string cipherText = "";

            foreach (char c in plainText)
            {
                if (Char.IsLetter(c))
                {
                    int letter = c;

                    letter = (c + key);


                    if (letter > 122)
                        letter -= 26;


                    char x = (char)letter;

                    cipherText += x;
                }


                //else    
                // cipherText += c;
            }

            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            if (key > 26)
                key = key % 26;

            else if (key < 0)
                key = (key % 26) + 26;

            string plainText = "";

            foreach (char c in cipherText)
            {
                if (Char.IsLetter(c))
                {
                    int letter = c;

                    letter = (c - key);

                    if (c >= 65 && c <= 90)
                    {
                        if (letter < 65)
                            letter += 26;
                    }

                    else if (c >= 97 && c <= 122)
                    {
                        if (letter < 97)
                            letter += 26;
                    }

                    char x = (char)letter;

                    plainText += x;
                }
            }
            return plainText;
            //throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            string alphabet = "abcdefghijklmnopqrstuvwxyz";

            for (int i = 0; i < 26; i++)
            {
                if (i == alphabet[i]) { return i; }

            }
            int letterP = plainText[0];
            int letterC = (char.ToLower(cipherText[0]));

            if (letterC == letterP) return 0;

            if ((letterP - letterC) < 0)
            {
                return (letterC - letterP) % 26;

            }
            else
            {
                return (letterC - letterP) + 26;

            }

            //throw new NotImplementedException();
        }
    }
}