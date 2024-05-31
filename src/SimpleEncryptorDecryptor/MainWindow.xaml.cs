using System.IO;
using System.Security.Cryptography;
using System;
using System.Text;
using System.Windows;
using System.Windows.Navigation;
using System.Diagnostics;
using System.Linq;

namespace SimpleEncryptorDecryptor
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Handles the RequestNavigate event for a Hyperlink, opening the specified URI in the default web browser.
        /// </summary>
        /// <param name="sender">The object that raised the event.</param>
        /// <param name="e">The event arguments containing the URI to navigate to.</param>
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

        /// <summary>
        /// Event handler for the Decrypt button click.
        /// </summary>
        /// <param name="sender">The object that raised the event.</param>
        /// <param name="e">The event arguments.</param>
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

        /// <summary>
        /// Event handler for the Encrypt button click.
        /// </summary>
        /// <param name="sender">The object that raised the event.</param>
        /// <param name="e">The event arguments.</param>
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
        // Encrypts a string using the provided encryption key.
        public static string Encrypt(string clearText, string key)
        {
            // Constants for encryption
            const int KeySize = 128;
            const int DerivationIterations = 1000;

            // Generate random bytes for salt and initialization vector (IV)
            var saltStringBytes = New128BitsOfRandomEntropy();
            var ivStringBytes = New128BitsOfRandomEntropy();

            // Convert the clear text to bytes
            var plainTextBytes = Encoding.UTF8.GetBytes(clearText);

            // Derive a key from the password and salt using PBKDF2
            using var password = new Rfc2898DeriveBytes(key, saltStringBytes, DerivationIterations, HashAlgorithmName.SHA256);
            var keyBytes = password.GetBytes(KeySize / 8);

            // Create an AES encryption algorithm
            using var symmetricKey = Aes.Create();
            symmetricKey.BlockSize = 128;
            symmetricKey.Mode = CipherMode.CBC;
            symmetricKey.Padding = PaddingMode.PKCS7;

            // Create an encryptor
            using var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes);

            // Create memory streams for encryption
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

            // Write the encrypted data to the memory stream
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();

            // Combine salt, IV, and encrypted data into the final cipher text
            var cipherTextBytes = saltStringBytes;
            cipherTextBytes = [.. cipherTextBytes, .. ivStringBytes];
            cipherTextBytes = [.. cipherTextBytes, .. memoryStream.ToArray()];

            // Close streams and return the Base64-encoded cipher text
            memoryStream.Close();
            cryptoStream.Close();

            // Convert the combined data (salt, IV, and encrypted data) to a Base64-encoded string
            return Convert.ToBase64String(cipherTextBytes);
        }

        // Decrypts a cipher text using the specified key.
        public static string Decrypt(string cipherText, string key)
        {
            // Constants for decryption
            const int KeySize = 128;
            const int DerivationIterations = 1000;

            // Convert the base64-encoded cipher text to bytes
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);

            // Extract the salt and IV (Initialization Vector) from the cipher text
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(KeySize / 8).ToArray();
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(KeySize / 8).Take(KeySize / 8).ToArray();

            // Extract the actual cipher text
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((KeySize / 8) * 2)
                .Take(cipherTextBytesWithSaltAndIv.Length - ((KeySize / 8) * 2)).ToArray();

            // Derive the encryption key from the provided key and salt
            using var password = new Rfc2898DeriveBytes(key, saltStringBytes, DerivationIterations, HashAlgorithmName.SHA256);
            var keyBytes = password.GetBytes(KeySize / 8);

            // Create an AES cipher with the derived key
            using var symmetricKey = Aes.Create();
            symmetricKey.BlockSize = 128;
            symmetricKey.Mode = CipherMode.CBC;
            symmetricKey.Padding = PaddingMode.PKCS7;

            // Create a decryptor with the key and IV
            using var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes);
            using var memoryStream = new MemoryStream(cipherTextBytes);
            using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

            // Read the decrypted data into plainTextBytes
            var plainTextBytes = new byte[cipherTextBytes.Length];
            var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

            // Close streams and return the Base64-encoded plain text
            memoryStream.Close();
            cryptoStream.Close();

            // Convert the decrypted bytes to a UTF-8 encoded string
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
        }

        // Generates 128 bits of random entropy (16 bytes) using a pseudo-random number generator.
        private static byte[] New128BitsOfRandomEntropy()
        {
            // Create an array of 16 bytes, which equals 128 bits.
            var randomBytes = new byte[16];

            // Initialize a random number generator.
            var random = new Random();

            // Generate random bytes and fill the array.
            random.NextBytes(randomBytes);

            // Return the generated random entropy (128 bits).
            return randomBytes;
        }
        #endregion
    }
}