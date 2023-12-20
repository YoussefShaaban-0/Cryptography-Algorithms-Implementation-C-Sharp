using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            string key = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int keyIndex;
                keyIndex = cipherText[i] - plainText[i];
                if (keyIndex < 0)
                    keyIndex += 26;
                keyIndex += 97;
                char x = (char)keyIndex;
                key += x;
            }
            string keystream = "";
            char x1 = key[0];
            char x2 = key[1];
            char x3 = key[2];

            for (int i = 3; i < key.Length; i++)
            {
                if (x1 == key[i] && x2 == key[i + 1] && x3 == key[i + 2])
                {
                    for (int j = 0; j < i; j++)
                    {
                        keystream += key[j];
                    }
                    break;
                }
            }
            return keystream;
            // throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string keystream = "";
            cipherText = cipherText.ToLower();
            if (cipherText.Length > key.Length)
            {
                for (int i = 0; i < cipherText.Length; i++)
                {
                    int l;
                    l = i % key.Length;
                    keystream += key[l];
                }
            }
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int keyIndex;
                keyIndex = cipherText[i] - keystream[i];
                if (keyIndex < 0)
                    keyIndex += 26;
                keyIndex += 97;
                char x = (char)keyIndex;
                plainText += x;
            }
            return plainText;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string keystream = "";
            if (plainText.Length > key.Length)
            {
                for (int i = 0; i < plainText.Length; i++)
                {
                    int l;
                    l = i % key.Length;
                    keystream += key[l];
                }
            }
            string cipherText = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                int keyIndex;
                keyIndex = ((plainText[i] - 97) % 26) + keystream[i];
                if (keyIndex > 122)
                    keyIndex -= 26;
                char x = (char)keyIndex;
                cipherText += x;
            }
            return cipherText;
            //throw new NotImplementedException();
        }
    }
}