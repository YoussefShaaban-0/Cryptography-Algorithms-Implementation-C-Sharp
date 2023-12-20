using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            // C = M^e mod p*q
            int pq = p * q;
            int ressult = 1;
            // loop from 1
            // and mak this ecuation M^e mod p*q
            for (int i = 1; i <= e; i++)
            {
                ressult = (ressult * M) % pq;
            }
            return ressult;
        }

        public int  Decrypt(int p, int q, int C, int e)
        {
            // M = C^-1 mod p*q 
            // D = E^-1 mod Φ 
            ExtendedEuclid EXtend = new ExtendedEuclid();
            int pq = p * q;
            // get invers of e using Extended Euclidean Algorithm
            e = EXtend.GetMultiplicativeInverse(e, (p - 1) * (q - 1));
            int result = 1;
            // loop from 1 to e 
            // and mak this ecuation M^e mod p*q
            for (int i = 1; i <= e; i++)
            {
                result = (result * C) % pq;
            }
            return result;
        }
    }
}
