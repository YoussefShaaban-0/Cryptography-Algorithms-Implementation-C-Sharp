using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            string key = "";
            string keystream = "";
            string letters = "abcdefghijklmnopqrstuvwxyz";
            int i = 0;
            while (i < cipherText.Length)
            {
                key = key + letters[((letters.IndexOf(cipherText[i]) - letters.IndexOf(plainText[i])) + 26) % 26];
                i++;
            }
            keystream = keystream + key[0];

            int x = 1;
            while (x < key.Length)
            {

                int res = string.Compare(cipherText, Encrypt(plainText, keystream));
                if (res == 0)
                {
                    return keystream;

                }
                keystream = keystream + key[x];
                x++;
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string keystream = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            int clength = cipherText.Length;
            string plaintext = "";
            cipherText = cipherText.ToLower();

            for (int i = 0; i < cipherText.Length; i++)
            {

                int ind = (cipherText[i] - key[i]) % 26;
                if (ind < 0)
                {
                    ind = (ind + 26) % 26;
                }
                plaintext += alphabet[ind];
                key += alphabet[ind];
            }
            return plaintext.ToLower();

        }

        public string Encrypt(string plainText, string key)
        {
            string keystream = "";
            if (plainText.Length > key.Length)
            {
                for (int i = 0; i < plainText.Length; i++)
                {
                    int l;
                    l = i % plainText.Length;
                    key += plainText[l];

                    if (keystream.Length == plainText.Length)
                        break;

                }

            }
            string cipherText = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                int keyIndex;
                keyIndex = ((plainText[i] - 97) % 26) + key[i];
                if (keyIndex > 122)
                    keyIndex -= 26;
                char x = (char)keyIndex;
                cipherText += x;
            }
            return cipherText;
            // throw new NotImplementedException();
        }
    }
}
