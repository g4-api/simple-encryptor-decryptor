using System;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Navigation;

namespace SimpleEncryptorDecryptor
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        // Handles the RequestNavigate event for a Hyperlink, opening the specified URI in the default web browser.
        private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            // Create ProcessStartInfo to configure how the process should start
            var processStartInfo = new ProcessStartInfo(e.Uri.AbsoluteUri)
            {
                UseShellExecute = true // Use the default shell execute behavior to open the URI in the default web browser
            };

            // Start the process using the specified URI
            Process.Start(processStartInfo);

            // Mark the event as handled to prevent further processing by the Hyperlink control
            e.Handled = true;
        }

        // Event handler for the Decrypt button click.
        private void BtnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            // Retrieve the key and cipher text from the input fields
            var key = TxbKey.Text;
            var cipherText = TxbInput.Text;

            // Check if either the key or cipher text is empty
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(cipherText))
            {
                // If either is empty, exit the method
                return;
            }

            // Call the Decrypt method and update the result text box with the decrypted text
            TxbResult.Text = Decrypt(cipherText, key);
        }

        // Event handler for the Encrypt button click.
        private void BtnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            // Retrieve the key and clear text from the input fields
            var key = TxbKey.Text;
            var clearText = TxbInput.Text;

            // Check if either the key or clear text is empty
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(clearText))
            {
                // If either is empty, exit the method
                return;
            }

            // Call the Encrypt method and update the result text box with the encrypted text
            TxbResult.Text = Encrypt(clearText, key);
        }

        #region *** Encryption ***
        // Encrypts a UTF-8 string using password-based AES encryption.
        private static string Encrypt(string clearText, string key)
        {
            // Size of the random salt used for PBKDF2 key derivation (128-bit)
            const int SaltSizeBytes = 16;

            // Size of the AES initialization vector (AES block size is 128-bit)
            const int IvSizeBytes = 16;

            // Size of the derived AES key (256-bit)
            const int KeySizeBytes = 32;

            // Number of PBKDF2 iterations to slow down brute-force attacks
            const int DerivationIterations = 100_000;

            // Generate a cryptographically secure random salt
            var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);

            // Generate a cryptographically secure random initialization vector
            var iv = RandomNumberGenerator.GetBytes(IvSizeBytes);

            // Convert the plaintext string into UTF-8 encoded bytes
            var plainTextBytes = Encoding.UTF8.GetBytes(clearText);

            // Derive a strong encryption key from the password and salt using PBKDF2
            var keyBytes = Rfc2898DeriveBytes.Pbkdf2(
                password: key,
                salt: salt,
                iterations: DerivationIterations,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: KeySizeBytes);

            // Create and configure the AES encryption algorithm
            using var aes = Aes.Create();
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            // Create an encryptor using the derived key and generated IV
            using var encryptor = aes.CreateEncryptor(keyBytes, iv);

            // Encrypt the plaintext bytes into memory
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();

            // Retrieve the encrypted bytes from the memory stream
            var cipherTextBytes = memoryStream.ToArray();

            // Allocate a buffer to store salt + IV + ciphertext
            var output = new byte[salt.Length + iv.Length + cipherTextBytes.Length];

            // Copy salt to the beginning of the output buffer
            Buffer.BlockCopy(salt, 0, output, 0, salt.Length);

            // Copy IV immediately after the salt
            Buffer.BlockCopy(iv, 0, output, salt.Length, iv.Length);

            // Copy ciphertext after the IV
            Buffer.BlockCopy(
                cipherTextBytes,
                0,
                output,
                salt.Length + iv.Length,
                cipherTextBytes.Length);

            // Encode the final payload as Base64 for safe storage or transport
            return Convert.ToBase64String(output);
        }

        // Decrypts a Base64-encoded payload produced byEncrypt.
        private static string Decrypt(string cipherText, string key)
        {
            // Size of the salt that prefixes the payload (must match Encrypt)
            const int SaltSizeBytes = 16;

            // Size of the IV that follows the salt (must match Encrypt)
            const int IvSizeBytes = 16;

            // Size of the derived AES key (256-bit, must match Encrypt)
            const int KeySizeBytes = 32;

            // PBKDF2 iteration count (must match Encrypt)
            const int DerivationIterations = 100_000;

            // Decode the Base64 payload into raw bytes: [salt | iv | ciphertext]
            var payloadBytes = Convert.FromBase64String(cipherText);

            // Validate the payload is long enough to contain at least salt + iv + 1 byte of ciphertext
            var minimumLength = SaltSizeBytes + IvSizeBytes + 1;
            if (payloadBytes.Length < minimumLength)
            {
                throw new ArgumentException("Cipher text is invalid or too short.", nameof(cipherText));
            }

            // Extract salt from the start of the payload
            var salt = new byte[SaltSizeBytes];
            Buffer.BlockCopy(payloadBytes, 0, salt, 0, SaltSizeBytes);

            // Extract IV immediately after the salt
            var iv = new byte[IvSizeBytes];
            Buffer.BlockCopy(payloadBytes, SaltSizeBytes, iv, 0, IvSizeBytes);

            // Extract ciphertext (everything after salt + IV)
            var cipherOffset = SaltSizeBytes + IvSizeBytes;
            var cipherLength = payloadBytes.Length - cipherOffset;
            var cipherBytes = new byte[cipherLength];
            Buffer.BlockCopy(payloadBytes, cipherOffset, cipherBytes, 0, cipherLength);

            // Derive the same key bytes from the password and extracted salt
            var keyBytes = Rfc2898DeriveBytes.Pbkdf2(
                password: key,
                salt: salt,
                iterations: DerivationIterations,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: KeySizeBytes);

            // Create and configure the AES algorithm for decryption
            using var aes = Aes.Create();
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            // Create a decryptor using the derived key and extracted IV
            using var decryptor = aes.CreateDecryptor(keyBytes, iv);

            // Decrypt by streaming ciphertext through CryptoStream and reading UTF-8 text
            using var memoryStream = new MemoryStream(cipherBytes);
            using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            using var reader = new StreamReader(cryptoStream, Encoding.UTF8);

            // Read and return the decrypted plaintext
            return reader.ReadToEnd();
        }
        #endregion
    }
}
