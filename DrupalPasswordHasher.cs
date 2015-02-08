using System;
using System.Collections;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNet.Identity;

namespace Drupal.Core
{
    public class DrupalPasswordHasher : IPasswordHasher
    {
        protected const int DrupalHashCount = 15;
        protected const int DrupalMinHashCount = 7;
        protected const int DrupalMaxHashCount = 30;
        protected const int DrupalHashLength = 55;
        protected const String PasswordItoA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        public PasswordVerificationResult VerifyHashedPassword(String hashedPassword, String providedPassword)
        {
            var legacyHash = false;

            if (hashedPassword.Substring(0, 2) == "U$")
            {
                // This may be an updated password from user_update_7000(). Such hashes
                // have 'U' added as the first character and need an extra md5().
                hashedPassword = hashedPassword.Substring(1);
                legacyHash = true;

                var algo = MD5.Create();
                var passwordBytes = algo.ComputeHash(Encoding.ASCII.GetBytes(providedPassword));
                providedPassword = PasswordHexEncode(passwordBytes);
            }

            var type = hashedPassword.Substring(0, 3);

            switch (type)
            {
                case "$S$":
                    // A normal Drupal 7 password using sha512.
                    if (VerifyHashedPasswordD7(DrupalPasswordHasherAlgorithm.SHA512, hashedPassword, providedPassword))
                    {
                        // Check if this is an old password hash format
                        if (UserNeedsNewHash(hashedPassword) || legacyHash)
                            return PasswordVerificationResult.SuccessRehashNeeded;
                        
                        return PasswordVerificationResult.Success;
                    }
                    else
                    {
                        return PasswordVerificationResult.Failed;
                    }
                case "$H$":
                    // phpBB3 uses "$H$" for the same thing as "$P$".
                case "$P$":
                    // A phpass password generated using md5.  This is an
                    // imported password or from an earlier Drupal version.
                    if (VerifyHashedPasswordD7(DrupalPasswordHasherAlgorithm.MD5, hashedPassword, providedPassword))
                    {
                        // Check if this is an old password hash format
                        if (UserNeedsNewHash(hashedPassword) || legacyHash)
                            return PasswordVerificationResult.SuccessRehashNeeded;

                        return PasswordVerificationResult.Success;
                    }
                    else
                    {
                        return PasswordVerificationResult.Failed;
                    }
                default:
                    return PasswordVerificationResult.Failed; // unknown format marker
            }
        }

        protected static bool VerifyHashedPasswordD7(DrupalPasswordHasherAlgorithm hashAlgorithm, String hashedPassword, String providedPassword)
        {
            // The first 12 characters of an existing hash are its setting string.
            // The first 3 characters specify the Drupal version.  ex: $S$ = Drupal 7
            // The fourth character specifies the Log2 value based on the Base64 String.  ex: D = 15
            // The last 8 characters are the salt.
            var settings = hashedPassword.Substring(0, 12);

            if (settings[0] != '$' || settings[2] != '$')
                return false;
            var countLog2 = PasswordGetCountLog2(settings);

            // Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
            if (countLog2 < DrupalMinHashCount || countLog2 > DrupalMaxHashCount)
                return false;

            var salt = settings.Substring(4, 8);

            // Hashes must have an 8 character salt.
            if (salt.Length != 8)
                return false;

            // Convert the base 2 logarithm into an integer.
            var count = 1 << countLog2;

            HashAlgorithm algorithm;

            // Drupal 7 uses SHA512 as it's hash algorithm
            if (hashAlgorithm == DrupalPasswordHasherAlgorithm.SHA512)
            {
                algorithm = SHA512.Create();
            }
            else if (hashAlgorithm == DrupalPasswordHasherAlgorithm.MD5)
            {
                algorithm = MD5.Create();
            }
            else
            {
                return false;
            }

            var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(salt + providedPassword));
            var passwordBytes = Encoding.ASCII.GetBytes(providedPassword);

            do
            {
                var saltedPassword = new byte[hash.Length + passwordBytes.Length];
                Buffer.BlockCopy(hash, 0, saltedPassword, 0, hash.Length);
                Buffer.BlockCopy(passwordBytes, 0, saltedPassword, hash.Length, passwordBytes.Length);

                hash = algorithm.ComputeHash(saltedPassword);
                count--;
            } while (count > 0);

            var output = settings + PasswordBase64Encode(hash);
            var expectedLength = 12 + Math.Ceiling((decimal)(8 * Encoding.ASCII.GetString(hash).Length) / 6);

            if (output.Length != expectedLength)
                return false;

            var hashedProvidedPassword = output.Substring(0, DrupalHashLength);

            return String.Compare(hashedPassword, hashedProvidedPassword, StringComparison.Ordinal) == 0;
        }

        public String HashPassword(String providedPassword)
        {
            return HashPassword(providedPassword, DrupalHashCount);
        }

        public String HashPassword(String providedPassword, int countLog2)
        {
            if (providedPassword == null)
                throw new ArgumentNullException("providedPassword");

            if (countLog2 == 0)
                // Use the standard iteration count.
                countLog2 = DrupalHashCount;

            return HashPasswordD7(providedPassword, PasswordGenerateSalt(countLog2));
        }

        protected static String HashPasswordD7(String providedPassword, String settings)
        {
            var countLog2 = PasswordGetCountLog2(settings);

            var salt = settings.Substring(4, 8);

            // Hashes must have an 8 character salt.
            if (salt.Length != 8)
                return String.Empty;

            // Convert the base 2 logarithm into an integer.
            var count = 1 << countLog2;

            // Drupal 7 uses SHA512 as it's hash algorithm
            var algorithm = SHA512.Create();

            var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(salt + providedPassword));
            var passwordBytes = Encoding.ASCII.GetBytes(providedPassword);

            do
            {
                var saltedPassword = new byte[hash.Length + passwordBytes.Length];
                Buffer.BlockCopy(hash, 0, saltedPassword, 0, hash.Length);
                Buffer.BlockCopy(passwordBytes, 0, saltedPassword, hash.Length, passwordBytes.Length);

                hash = algorithm.ComputeHash(saltedPassword);
                count--;
            } while (count > 0);

            var output = settings + PasswordBase64Encode(hash);
            var expectedLength = 12 + Math.Ceiling((decimal)(8 * Encoding.ASCII.GetString(hash).Length) / 6);

            return output.Length == expectedLength ? output.Substring(0, DrupalHashLength) : String.Empty;
        }

        protected static String PasswordBase64Encode(byte[] input)
        {
            var output = new StringBuilder();
            var i = 0;

            // This is the algorithm that Drupal uses to Base64 encode a byte array
            do
            {
                var value = Convert.ToInt64(input[i++]);
                output.Append(PasswordItoA64[(int)value & 0x3f]);

                if (i < input.Length)
                    value |= Convert.ToInt64(input[i]) << 8;
                output.Append(PasswordItoA64[(int)(value >> 6) & 0x3f]);

                if (i++ >= input.Length)
                    break;
                if (i < input.Length)
                    value |= Convert.ToInt64(input[i]) << 16;
                output.Append(PasswordItoA64[(int)(value >> 12) & 0x3f]);

                if (i++ >= input.Length)
                    break;
                output.Append(PasswordItoA64[(int)(value >> 18) & 0x3f]);
            } while (i < input.Length);

            return output.ToString();
        }

        protected static String PasswordHexEncode(byte[] bytes)
        {
            var result = new StringBuilder(bytes.Length * 2);

            foreach (var b in bytes)
                result.AppendFormat("{0:x2}", b);

            return result.ToString();
        }

        protected static int PasswordGetCountLog2(String setting)
        {
            // Drupal stores the Log2 count as the 4th character in the hash
            return PasswordItoA64.IndexOf(setting[3]);
        }

        protected static int PasswordEnforceLog2Boundaries(int countLog2)
        {
            if (countLog2 < DrupalMinHashCount)
                return DrupalMinHashCount;
            if (countLog2 > DrupalMaxHashCount)
                return DrupalMaxHashCount;

            return countLog2;
        }

        protected static String PasswordGenerateSalt(int countLog2)
        {
            var output = new StringBuilder();
            output.Append("$S$");

            // Ensure that countLog2 is within set bounds.
            countLog2 = PasswordEnforceLog2Boundaries(countLog2);
            // We encode the final log2 iteration count in base 64.
            output.Append(PasswordItoA64[countLog2]);
            // 6 bytes is the standard salt for a portable phpass hash.
            output.Append(PasswordBase64Encode(DrupalRandomBytes(6)));

            return output.ToString();
        }

        protected static byte[] DrupalRandomBytes(int count)
        {
            var random = new Random();
            var bytes = new byte[count];

            random.NextBytes(bytes);
            return bytes;
        }

        protected static bool UserNeedsNewHash(String hashedPassword)
        {
            if (String.Compare(hashedPassword.Substring(0, 3), "$S$") != 0)
                return true;

            var countLog2 = PasswordGetCountLog2(hashedPassword);

            return PasswordEnforceLog2Boundaries(countLog2) != countLog2;
        }
    }
}
