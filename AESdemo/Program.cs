using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AESdemo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter a sentence to encrypt: ");

            string plainText = Console.ReadLine();

            Aes myAes = Aes.Create();
            byte[] encrypted = StringEncryptor(plainText, myAes.Key, myAes.IV);
            string encryptedString = BitConverter.ToString(encrypted).Replace("-", string.Empty).ToLower();
            string decrypted = StringDecryptor(encrypted, myAes.Key, myAes.IV);
            int keySize = myAes.KeySize;

            Console.WriteLine("Original plain text: " + plainText);
            Console.ReadKey();
            Console.WriteLine();
            Console.WriteLine("Using a key size of " + keySize + " bits, this is the");
            Console.WriteLine("encrypted text: " + encryptedString);
            Console.ReadKey();
            Console.WriteLine();
            Console.WriteLine("And finally, here is our original text after having");
            Console.WriteLine("been decrypted: " + decrypted);
            Console.WriteLine("(Press Enter to exit)");
            Console.ReadKey();
        }

        private static byte[] StringEncryptor(string plainText, byte[] key, byte[] iV)
        {
            if (plainText == null || plainText.Length < 1)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length < 1)
                throw new ArgumentNullException("key");
            if (iV == null || iV.Length < 1)
                throw new ArgumentNullException("iV");

            byte[] encrypted;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        private static string StringDecryptor(byte[] encrypted, byte[] key, byte[] iV)
        {
            if (encrypted == null || encrypted.Length < 1)
                throw new ArgumentNullException("encrypted");
            if (key == null || key.Length < 1)
                throw new ArgumentNullException("key");
            if (iV == null || iV.Length < 1)
                throw new ArgumentNullException("iV");

            string plainText = string.Empty;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(encrypted))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plainText;
        }
    }
}
