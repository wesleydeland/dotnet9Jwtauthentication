using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using DotnetAuthentication.Data;
using DotnetAuthentication.DTOs;
using DotnetAuthentication.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace DotnetAuthentication.Services;

public interface IAuthService
{
    Task<User?> RegisterAsync(UserDto userDto);
    Task<TokenResponseDto?> LoginAsync(UserDto userDto);
    Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto requestDto);
}

public class AuthService(AppDbContext _dbContext, IConfiguration _configuration) : IAuthService
{
    public async Task<User?> RegisterAsync(UserDto userDto)
    {
        if (await _dbContext.Users.AnyAsync(u => u.UserName == userDto.UserName))
        {
            return null;
        }
        
        var newUser = new User();
        var hashedPassword = new PasswordHasher<User>()
            .HashPassword(newUser, userDto.Password);
        
        newUser.UserName = userDto.UserName;
        newUser.PasswordHash = hashedPassword;
        
        _dbContext.Users.Add(newUser);
        await _dbContext.SaveChangesAsync();

        return newUser;
    }

    public async Task<TokenResponseDto?> LoginAsync(UserDto userDto)
    {
        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.UserName == userDto.UserName);

        if (user is null)
        {
            return null;
        }
        if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, userDto.Password)
            == PasswordVerificationResult.Failed)
        {
            return null;
        }

        return await CreateTokenResponse(user);
    }

    public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto requestDto)
    {
        var user = await ValidateRefreshTokenAsync(requestDto);

        if (user is null)
            return null;

        return await CreateTokenResponse(user);
    }

    private async Task<TokenResponseDto?> CreateTokenResponse(User user)
    {
        return new TokenResponseDto
        {
            AccessToken = CreateToken(user),
            RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
        };
    }

    private string CreateToken(User user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(type: ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Role, user.Role)
        };

        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSettings:Token")!));
        
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

        var tokenDescriptor = new JwtSecurityToken(
            issuer: _configuration.GetValue<string>("AppSettings:Issuer"),
            audience: _configuration.GetValue<string>("AppSettings:Audience"),
            claims: claims,
            expires: DateTime.UtcNow.AddDays(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }

    private async Task<User?> ValidateRefreshTokenAsync(RefreshTokenRequestDto requestDto)
    {
        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Id == requestDto.UserId);

        if (user is null || user.RefreshToken != requestDto.RefreshToken || user.RefreshTokenExpiry <= DateTime.UtcNow)
        {
            return null;
        }
        
        return user;
    }
    
    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
    {
        var refreshToken = GenerateRefreshToken();
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
        await _dbContext.SaveChangesAsync();
        return refreshToken;
    }
}