using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
			int x = 0;
			for (int i = 2; i <= plainText.Length; i++)
			{

				char[,] rail = new char[i, plainText.Length];

				// filling the rail matrix to distinguish filled
				// spaces from blank ones
				for (int z = 0; z < i; z++)
					for (int j = 0; j < plainText.Length; j++)
						rail[z, j] = '\n';

				bool dirDown = false;
				int row = 0, col = 0;

				for (int c = 0; c < plainText.Length; c++)
				{
					// check the direction of flow
					// reverse the direction if we've just
					// filled the top or bottom rail
					if (row == 0 || row == i - 1)
						dirDown = !dirDown;

					// fill the corresponding alphabet
					rail[row, col++] = plainText[c];

					// find the next row using direction flag
					if (dirDown)
						row++;
					else
						row = 0;
				}

				// now we can construct the cipher using the rail
				// matrix
				string result = "";
				for (int a = 0; a < i; a++)
					for (int j = 0; j < plainText.Length; j++)
						if (rail[a, j] != '\n')
							result += rail[a, j];

				////////////////////////////////////////////////////
				string s = result.ToLower();
				string g = cipherText.ToLower();
				if (s.Equals(g))
				{
					x = i;
					break;
				}
			}
			return x;
			//throw new NotImplementedException();
		}

        public string Decrypt(string cipherText, int key)
        {
			char[,] rail = new char[key, cipherText.Length];
			for (int i = 0; i < key; i++)
				for (int j = 0; j < cipherText.Length; j++)
					rail[i, j] = '\n';

			bool dirDown = true;
			int row = 0, col = 0;

			// mark the places with '0'
			for (int i = 0; i < cipherText.Length; i++)
			{
				// check the direction of flow
				if (row == 0)
					dirDown = true;
				if (row == key - 1)
					dirDown = false;

				// place the marker
				rail[row, col++] = '0';

				// find the next row using direction flag
				if (dirDown)
					row++;
				else
					row = 0;
			}

			// now we can construct the fill the rail matrix
			int index = 0;
			for (int i = 0; i < key; i++)
				for (int j = 0; j < cipherText.Length; j++)
					if (rail[i, j] == '0' && index < cipherText.Length)
						rail[i, j] = cipherText[index++];

			// create the result string
			string result = "";
			row = 0;
			col = 0;

			// iterate through the rail matrix
			for (int i = 0; i < cipherText.Length; i++)
			{
				// check the direction of flow
				if (row == 0)
					dirDown = true;
				if (row == key - 1)
					dirDown = false;

				// place the marker
				if (rail[row, col] != '0')
					result += rail[row, col++];

				// find the next row using direction flag
				if (dirDown)
					row++;
				else
					row = 0;
			}
			return result;
			// throw new NotImplementedException();
		}

        public string Encrypt(string plainText, int key)
        {
			char[,] rail = new char[key, plainText.Length];

			for (int i = 0; i < key; i++)
				for (int j = 0; j < plainText.Length; j++)
					rail[i, j] = '\n';

			bool dirDown = false;
			int row = 0, col = 0;

			for (int i = 0; i < plainText.Length; i++)
			{

				if (row == 0 || row == key - 1)
					dirDown = !dirDown;

				rail[row, col++] = plainText[i];

				// find the next row using direction flag
				if (dirDown)
					row++;
				else
					row = 0;
			}

			// now we can construct the cipher using the rail
			// matrix
			string result = "";
			for (int i = 0; i < key; i++)
				for (int j = 0; j < plainText.Length; j++)
					if (rail[i, j] != '\n')
						result += rail[i, j];

			return result;
			//throw new NotImplementedException();
		}
    }
}
