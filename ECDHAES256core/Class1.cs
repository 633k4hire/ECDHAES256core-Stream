using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace ECDHAES256core
{
    using System;
    using System.IO;
    using System.Numerics;
    using System.Security.Cryptography;
    using System.Threading;
    using System.Threading.Tasks;

    using static ECDHAES256core.KeyExchange;

    public class AES
    {
        public CNG Cng { get; set; }

        public AES()
        {
            CNG c = new CNG();

            Cng = c;
        }


        public CNG Encrypt(CNG c)
        {
            EncryptMessage(c.Key, c.PlaintextBytes, out c.EncryptedBytes, out c.Iv);
            c.PlaintextBytes = null;
            return c;
        }
        public void EncryptMessage(Byte[] key, Byte[] plaintextMessage, out Byte[] encryptedMessage, out Byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;
                aes.Padding = PaddingMode.PKCS7;
                using (MemoryStream ciphertext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                        cs.Close();
                        encryptedMessage = ciphertext.ToArray();
                    }
                }
            }
        }
        public void EncryptMessage(Byte[] key, Stream plaintextMessage, out Byte[] encryptedMessage, out Byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;
                aes.Padding = PaddingMode.PKCS7;
                using (MemoryStream ciphertext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        plaintextMessage.CopyTo(cs);
                        // cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                        cs.Close();
                        encryptedMessage = ciphertext.ToArray();
                    }
                }
            }
        }
        public MemoryStream EncryptMessage(Byte[] key, Stream plaintextMessage, out Byte[] iv)
        {
            MemoryStream ms = new MemoryStream();

            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream ciphertext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        plaintextMessage.CopyTo(cs);
                        // cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                        cs.Close();
                        //ciphertext.CopyTo(ms);
                        var buf = ciphertext.ToArray();
                        ms.Write(buf, 0, buf.Length);
                    }

                }
            }

            return ms;

        }
        public async Task<CNG> EncryptAsync(Byte[] key, Byte[] plaintextMessage)
        {
            CNG cng = new CNG();
            cng.Key = key;
            cng.PlaintextBytes = plaintextMessage;
            return await Task.Factory.StartNew(() =>
            {
                using (Aes aes = new AesCryptoServiceProvider())
                {
                    aes.Key = key;
                    cng.Iv = aes.IV;
                    aes.Padding = PaddingMode.PKCS7;
                    using (MemoryStream ciphertext = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                            cs.Close();
                            cng.EncryptedBytes = ciphertext.ToArray();
                        }
                    }
                    return cng;
                }
            });
        }
        public async Task<CNG> EncryptAsync(Byte[] key, Stream plaintextMessage)
        {
            CNG cng = new CNG();
            cng.Key = key;
            cng.Stream = plaintextMessage;
            return await Task.Factory.StartNew(() =>
            {
                using (Aes aes = new AesCryptoServiceProvider())
                {
                    aes.Key = key;
                    cng.Iv = aes.IV;
                    aes.Padding = PaddingMode.PKCS7;
                    using (MemoryStream ciphertext = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            plaintextMessage.CopyTo(cs);
                            cs.Close();
                            cng.EncryptedBytes = ciphertext.ToArray();
                        }
                    }
                    return cng;
                }
            });
        }

        public CNG Decrypt(CNG c)
        {
            DecryptMessage(out c.PlaintextBytes, c.EncryptedBytes, c.Iv, c.Key);
            c.EncryptedBytes = null;
            c.Iv = null;
            return c;
        }
        public void DecryptMessage(out Byte[] plaintextBytes, Byte[] encryptedBytes, Byte[] iv, Byte[] bkey)
        {

            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = bkey;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;
                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedBytes, 0, encryptedBytes.Length);
                        cs.Close();
                        encryptedBytes = null;
                        plaintextBytes = plaintext.ToArray();
                    }
                }
            }
        }
        public void DecryptMessage(out Byte[] plaintextBytes, Stream encryptedBytes, Byte[] iv, Byte[] bkey)
        {

            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = bkey;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;
                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        encryptedBytes.CopyTo(cs);
                        cs.Close();
                        encryptedBytes = null;
                        plaintextBytes = plaintext.ToArray();
                    }
                }
            }
        }
        public Stream DecryptMessage(Stream encryptedBytes, Byte[] iv, Byte[] bkey)
        {
            MemoryStream ms = new MemoryStream();
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = bkey;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;
                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        encryptedBytes.CopyTo(cs);
                        cs.Close();
                        encryptedBytes = null;
                        plaintext.CopyTo(ms);
                    }
                }
            }
            return ms;
        }
        public async Task<CNG> DencryptAsync(Byte[] encryptedBytes, Byte[] iv, Byte[] bkey)
        {
            CNG cng = new CNG();
            cng.Key = bkey;
            cng.Iv = iv;
            cng.EncryptedBytes = encryptedBytes;
            return await Task.Factory.StartNew(() =>
            {
                using (Aes aes = new AesCryptoServiceProvider())
                {
                    aes.Key = cng.Key;
                    aes.IV = cng.Iv;
                    aes.Padding = PaddingMode.PKCS7;
                    // Decrypt the message
                    using (MemoryStream plaintext = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(encryptedBytes, 0, encryptedBytes.Length);
                            cs.Close();
                            encryptedBytes = null;
                            cng.PlaintextBytes = plaintext.ToArray();
                        }
                    }
                }
                return cng;
            });
        }
        public async Task<CNG> DencryptAsync(Stream encryptedStream, Byte[] iv, Byte[] bkey)
        {
            CNG cng = new CNG();
            cng.Key = bkey;
            cng.Iv = iv;
            cng.Stream = encryptedStream;
            return await Task.Factory.StartNew(() =>
            {
                using (Aes aes = new AesCryptoServiceProvider())
                {
                    aes.Key = cng.Key;
                    aes.IV = cng.Iv;
                    aes.Padding = PaddingMode.PKCS7;
                    // Decrypt the message
                    using (MemoryStream plaintext = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            encryptedStream.CopyTo(cs);
                            cs.Close();
                            cng.PlaintextBytes = plaintext.ToArray();
                        }
                    }
                }
                return cng;
            });
        }

    }
    public static class DiffieHellman
    {
        private static readonly Random Random = new Random();

        public static BigInteger PrivateKey(BigInteger primeP) => new BigInteger(Random.Next(1, (int)primeP - 1));

        public static BigInteger PublicKey(BigInteger primeP, BigInteger primeG, BigInteger privateKey) => BigInteger.ModPow(primeG, privateKey, primeP);

        public static BigInteger Secret(BigInteger primeP, BigInteger publicKey, BigInteger privateKey) => BigInteger.ModPow(publicKey, privateKey, primeP);

        private static RNGCryptoServiceProvider rngProvider = new RNGCryptoServiceProvider();
        private static byte[] someBytes;

        public static BigInteger GetCryptoPrime(int nBits = 512, bool onlyPositive = true)
        {
            rngProvider = new RNGCryptoServiceProvider();
            someBytes = new byte[nBits / 8];
            rngProvider.GetBytes(someBytes);

            BigInteger bg = new BigInteger(someBytes);
            if (onlyPositive && bg.Sign == -1) bg = bg * -1;

            rngProvider.Dispose();
            return bg;
        }
        public static Tuple<BigInteger, BigInteger> GetTwoCryptoPrimes(int nbitsOf1 = 512, int nbitsOf2 = 512, bool onlyPositive = true)
        {
            return Tuple.Create(GetCryptoPrime(nbitsOf1, onlyPositive), GetCryptoPrime(nbitsOf2, onlyPositive));
        }
        private static BigInteger IntegerSquareRoot(BigInteger value)
        {
            if (value > 0)
            {
                int bitLength = value.ToByteArray().Length * 8;
                BigInteger root = BigInteger.One << (bitLength / 2);
                while (!IsSquareRoot(value, root))
                {
                    root += value / root;
                    root /= 2;
                }
                return root;
            }
            else return 0;
        }

        private static Boolean IsSquareRoot(BigInteger n, BigInteger root)
        {
            BigInteger lowerBound = root * root;
            BigInteger upperBound = (root + 1) * (root + 1);
            return (n >= lowerBound && n < upperBound);
        }

        public static bool IsPrime(BigInteger value)
        {
            //Console.WriteLine("Checking if {0} is a prime number.", value);
            if (value < 3)
            {
                if (value == 2)
                {
                    //Console.WriteLine("{0} is a prime number.", value);
                    return true;
                }
                else
                {
                    //Console.WriteLine("{0} is not a prime number because it is below 2.", value);
                    return false;
                }
            }
            else
            {
                if (value % 2 == 0)
                {
                    //Console.WriteLine("{0} is not a prime number because it is divisible by 2.", value);
                    return false;
                }
                else if (value == 5)
                {
                    //Console.WriteLine("{0} is a prime number.", value);
                    return true;
                }
                else if (value % 5 == 0)
                {
                    //Console.WriteLine("{0} is not a prime number because it is divisible by 5.", value);
                    return false;
                }
                else
                {
                    // The only way this number is a prime number at this point is if it is divisible by numbers ending with 1, 3, 7, and 9.
                    AutoResetEvent success = new AutoResetEvent(false);
                    AutoResetEvent failure = new AutoResetEvent(false);
                    AutoResetEvent onesSucceeded = new AutoResetEvent(false);
                    AutoResetEvent threesSucceeded = new AutoResetEvent(false);
                    AutoResetEvent sevensSucceeded = new AutoResetEvent(false);
                    AutoResetEvent ninesSucceeded = new AutoResetEvent(false);
                    BigInteger squareRootedValue = IntegerSquareRoot(value);
                    Thread ones = new Thread(() =>
                    {
                        for (BigInteger i = 11; i <= squareRootedValue; i += 10)
                        {
                            if (value % i == 0)
                            {
                                //Console.WriteLine("{0} is not a prime number because it is divisible by {1}.", value, i);
                                failure.Set();
                            }
                        }
                        onesSucceeded.Set();
                    });
                    ones.Start();
                    Thread threes = new Thread(() =>
                    {
                        for (BigInteger i = 3; i <= squareRootedValue; i += 10)
                        {
                            if (value % i == 0)
                            {
                                //Console.WriteLine("{0} is not a prime number because it is divisible by {1}.", value, i);
                                failure.Set();
                            }
                        }
                        threesSucceeded.Set();
                    });
                    threes.Start();
                    Thread sevens = new Thread(() =>
                    {
                        for (BigInteger i = 7; i <= squareRootedValue; i += 10)
                        {
                            if (value % i == 0)
                            {
                                //Console.WriteLine("{0} is not a prime number because it is divisible by {1}.", value, i);
                                failure.Set();
                            }
                        }
                        sevensSucceeded.Set();
                    });
                    sevens.Start();
                    Thread nines = new Thread(() =>
                    {
                        for (BigInteger i = 9; i <= squareRootedValue; i += 10)
                        {
                            if (value % i == 0)
                            {
                                // Console.WriteLine("{0} is not a prime number because it is divisible by {1}.", value, i);
                                failure.Set();
                            }
                        }
                        ninesSucceeded.Set();
                    });
                    nines.Start();
                    Thread successWaiter = new Thread(() =>
                    {
                        AutoResetEvent.WaitAll(new WaitHandle[] { onesSucceeded, threesSucceeded, sevensSucceeded, ninesSucceeded });
                        success.Set();
                    });
                    successWaiter.Start();
                    int result = AutoResetEvent.WaitAny(new WaitHandle[] { success, failure });
                    try
                    {
                        successWaiter.Abort();
                    }
                    catch { }
                    try
                    {
                        ones.Abort();
                    }
                    catch { }
                    try
                    {
                        threes.Abort();
                    }
                    catch { }
                    try
                    {
                        sevens.Abort();
                    }
                    catch { }
                    try
                    {
                        nines.Abort();
                    }
                    catch { }
                    if (result == 1)
                    {
                        return false;
                    }
                    else
                    {
                        //Console.WriteLine("{0} is a prime number.", value);
                        return true;
                    }
                }
            }
        }
    }
    public class KeyExchange
    {
        public KeyExchange()
        {
            //var primes = DiffieHellman.GetTwoCryptoPrimes();

            //var primeP = new BigInteger(primes.Item1.ToByteArray());
            //var primeG = new BigInteger(primes.Item2.ToByteArray());

            //var privateKeyA = DiffieHellman.PrivateKey(primeP);
            //var privateKeyB = DiffieHellman.PrivateKey(primeP);

            //var publicKeyA = DiffieHellman.PublicKey(primeP, primeG, privateKeyA);
            //var publicKeyB = DiffieHellman.PublicKey(primeP, primeG, privateKeyB);

            //var secretA = DiffieHellman.Secret(primeP, publicKeyB, privateKeyA);
            //var secretB = DiffieHellman.Secret(primeP, publicKeyA, privateKeyB);
        }
        public CNG A(CNG c)
        {
            //alice creates a public and private key
            c.Alice.P_G = c.Bob.P_G = DiffieHellman.GetTwoCryptoPrimes();
            c.Alice.PrivateKey = DiffieHellman.PrivateKey(c.Alice.P_G.Item1);
            c.Alice.PublicKey = DiffieHellman.PublicKey(c.Alice.P_G.Item1, c.Alice.P_G.Item2, c.Alice.PrivateKey);
            //check if bob has supplied public key yet
            if (c.Bob.PublicKey != null)
            {
                c.Bob.Key = c.Alice.Key = DiffieHellman.Secret(c.Alice.P_G.Item1, c.Bob.PublicKey, c.Alice.PrivateKey);
            }

            return c;
        }
        public CNG B(CNG c)
        {
            c.Alice.P_G = c.Bob.P_G = DiffieHellman.GetTwoCryptoPrimes();
            c.Bob.PrivateKey = DiffieHellman.PrivateKey(c.Bob.P_G.Item1);
            c.Bob.PublicKey = DiffieHellman.PublicKey(c.Bob.P_G.Item1, c.Bob.P_G.Item2, c.Bob.PrivateKey);
            if (c.Alice.PublicKey != null)
            {
                c.Bob.Key = c.Alice.Key = DiffieHellman.Secret(c.Bob.P_G.Item1, c.Alice.PublicKey, c.Bob.PrivateKey);
            }


            return c;
        }

        public class Alice
        {
            public Alice()
            {
                P_G = DiffieHellman.GetTwoCryptoPrimes();
                PrivateKey = DiffieHellman.PrivateKey(P_G.Item1);
                PublicKey = DiffieHellman.PublicKey(P_G.Item1, P_G.Item2, PrivateKey);
                //check if bob has supplied public key yet               
            }
            public bool MakeKey(BigInteger publicKey)
            {
                try
                {
                    PrivateKey = DiffieHellman.PrivateKey(P_G.Item1);
                    PublicKey = DiffieHellman.PublicKey(P_G.Item1, P_G.Item2, PrivateKey);
                    //check if bob has supplied public key yet
                    if (publicKey != null)
                    {
                        Key = DiffieHellman.Secret(P_G.Item1, publicKey, PrivateKey);
                    }
                    return true;
                }
                catch (Exception)
                {

                    return false;
                }
            }
            public BigInteger Key;
            public Byte[] Iv;
            public BigInteger PublicKey;
            public BigInteger PrivateKey;
            public Tuple<BigInteger, BigInteger> P_G;

        }
        public class Bob : Alice
        {
            public Bob() { }
            public Bob(Tuple<BigInteger, BigInteger> primes, BigInteger publicKey)
            {
                P_G = primes;
                PrivateKey = DiffieHellman.PrivateKey(P_G.Item1);
                PublicKey = DiffieHellman.PublicKey(P_G.Item1, P_G.Item2, PrivateKey);
                if (publicKey != null)
                {
                    Key = DiffieHellman.Secret(P_G.Item1, publicKey, PrivateKey);
                }
            }
        }
        public class CNG
        {
            public CNG()
            {
            }
            ~CNG()
            {
                Dispose();
            }
            public void Dispose()
            {
                Alice = null;
                Bob = null;
                Iv = null;
                EncryptedBytes = null;
                PlaintextBytes = null;
                Stream.Dispose();
                GC.Collect();
            }

            public Alice Alice = new Alice();
            public Bob Bob = new Bob();
            public Byte[] Key;
            public Byte[] Iv;
            public Byte[] EncryptedBytes;
            public Byte[] PlaintextBytes;
            internal Stream Stream;
        }

    }
}
