namespace PasswordManger.Models;

public class Account
{
    public int Id { get; set; }
    public string ServiceName { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public byte[] EncryptedPassword { get; set; } = [];
    public byte[] Nonce { get; set; } = [];
    public byte[] Tag { get; set; } = [];
    public string? Url { get; set; }
    public string? TwoFaSecret { get; set; }
    public string? RecoveryCodes { get; set; }
    public string? Notes { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}