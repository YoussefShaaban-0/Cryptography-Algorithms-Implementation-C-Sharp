using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            int Y = y;
            BigInteger K = Y;

            for (int i = 0; i < k - 1; i++)
            {

                K *= Y;

            }
            K = K % q;
            BigInteger C1 = alpha;
            for (int i = 0; i < k - 1; i++)
                C1 *= alpha;
            C1 = C1 % q;
            long C2 = 0;
            C2 = (((long)((K * m) % q)));
            List<long> cipher = new List<long>();

            cipher.Add((long)C1);
            cipher.Add((long)C2);
            return cipher;

            //throw new NotImplementedException();

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
                int a = 1;
                //get k= c1^x mod q 

                // loop to multply c1 by itself by x 
                for (int i = 1; i <= x; i++)
                {
                    a = (a * c1) % q;
                }

                // get k inveres=  (c1^x mod q )^-1 mod q 

                ExtendedEuclid EXtend = new ExtendedEuclid();
                int inv = EXtend.GetMultiplicativeInverse(a, q);
                // massage =  inverse * c2 mod q 
                int m = (c2 * inv) % q;
                return m;

        }
    }
}
