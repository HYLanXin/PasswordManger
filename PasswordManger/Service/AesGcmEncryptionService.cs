using System.Security.Cryptography;
using System.Text;

namespace PasswordManger.Service;

public class AesGcmEncryptionService
{
    private static readonly byte[] MasterKey = Encoding.UTF8.GetBytes("ThisIsMy32ByteLongMasterKeyForAES!");

    public (byte[] encrypted, byte[] nonce, byte[] tag) Encrypt(string plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var encrypted = new byte[plaintext.Length];

        using var aes = new AesGcm(MasterKey);
        aes.Encrypt(nonce, Encoding.UTF8.GetBytes(plaintext), encrypted, tag);

        return (encrypted, nonce, tag);
    }

    public string Decrypt(byte[] encrypted, byte[] nonce, byte[] tag)
    {
        var decrypted = new byte[encrypted.Length];
        using var aes = new AesGcm(MasterKey);
        aes.Decrypt(nonce, encrypted, tag, decrypted);
        return Encoding.UTF8.GetString(decrypted);
    }
}