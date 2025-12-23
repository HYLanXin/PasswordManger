using Microsoft.AspNetCore.Mvc;
using PasswordManger.Data;

namespace PasswordManger.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly ILogger<AuthController> _logger;

    public AuthController(ApplicationDbContext db, ILogger<AuthController> logger)
    {
        _db = db;
        _logger = logger;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var now = DateTime.UtcNow;
        var validPasswords = new[]
        {
            now.AddMinutes(-1).ToString("yyyyMMddHHmm"),
            now.ToString("yyyyMMddHHmm"),
            now.AddMinutes(1).ToString("yyyyMMddHHmm")
        };

        if (!validPasswords.Contains(request.Password))
        {
            await LogAudit("Login", "Failed");
            return Unauthorized("Invalid or expired password");
        }

        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var key = System.Text.Encoding.ASCII.GetBytes("your-very-long-secret-key-for-jwt-signing-here-32bytes+");
        var tokenDescriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(new[] {
                new System.Security.Claims.Claim("scope", "account_manager")
            }),
            Expires = DateTime.UtcNow.AddMinutes(10),
            Issuer = "AccountManager",
            Audience = "AccountManagerUsers",
            SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key),
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        await LogAudit("Login", "Success");
        return Ok(new { token = tokenString });
    }

    private async Task LogAudit(string action, string result)
    {
        var log = new Models.AuditLog
        {
            Action = $"{action} ({result})",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"]
        };
        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();
    }
}

public class LoginRequest
{
    public string Password { get; set; } = string.Empty;
}