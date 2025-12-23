using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PasswordManger.Data;
using PasswordManger.Service;
using Microsoft.EntityFrameworkCore;

namespace PasswordManger.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AccountsController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly AesGcmEncryptionService _encryption;

    public AccountsController(ApplicationDbContext db, AesGcmEncryptionService encryption)
    {
        _db = db;
        _encryption = encryption;
    }

    [HttpGet]
    public async Task<IActionResult> GetAccounts()
    {
        await LogAudit("ListAccounts");
        var accounts = await _db.Accounts
            .Select(a => new {
                a.Id,
                a.ServiceName,
                a.Username,
                a.Url,
                a.TwoFaSecret,
                a.Notes,
                a.CreatedAt
            })
            .ToListAsync();
        return Ok(accounts);
    }

    [HttpGet("{id}/password")]
    public async Task<IActionResult> GetPassword(int id)
    {
        var account = await _db.Accounts.FindAsync(id);
        if (account == null) return NotFound();

        try
        {
            var plainPassword = _encryption.Decrypt(account.EncryptedPassword, account.Nonce, account.Tag);
            await LogAudit("ViewPassword");
            return Ok(new { password = plainPassword });
        }
        catch
        {
            return StatusCode(500, "Decryption failed");
        }
    }

    [HttpPost]
    public async Task<IActionResult> CreateAccount([FromBody] CreateAccountRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.ServiceName) ||
            string.IsNullOrWhiteSpace(req.Username) ||
            string.IsNullOrWhiteSpace(req.Password))
        {
            return BadRequest("ServiceName, Username, and Password are required.");
        }

        var (encrypted, nonce, tag) = _encryption.Encrypt(req.Password);

        var account = new Models.Account
        {
            ServiceName = req.ServiceName,
            Username = req.Username,
            EncryptedPassword = encrypted,
            Nonce = nonce,
            Tag = tag,
            Url = req.Url,
            TwoFaSecret = req.TwoFaSecret,
            RecoveryCodes = req.RecoveryCodes,
            Notes = req.Notes
        };

        _db.Accounts.Add(account);
        await _db.SaveChangesAsync();
        await LogAudit("CreateAccount");
        return Ok(new { Id = account.Id });
    }

    private async Task LogAudit(string action)
    {
        var log = new Models.AuditLog
        {
            Action = action,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"]
        };
        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();
    }
}

public class CreateAccountRequest
{
    public string ServiceName { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? Url { get; set; }
    public string? TwoFaSecret { get; set; }
    public string? RecoveryCodes { get; set; }
    public string? Notes { get; set; }
}