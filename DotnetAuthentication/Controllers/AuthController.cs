using DotnetAuthentication.DTOs;
using DotnetAuthentication.Entities;
using DotnetAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetAuthentication.Controllers;

[ApiController, Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly IAuthService _authService;

    public AuthController(IConfiguration config, IAuthService authService)
    {
        _configuration = config;
        _authService = authService;
    }
    
    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserDto userDto)
    {
        var user = await _authService.RegisterAsync(userDto);

        if (user is null)
        {
            return BadRequest("Could not register user");
        }

        return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<TokenResponseDto>> Login(UserDto userDto)
    {
        var tokenResponse = await _authService.LoginAsync(userDto);
        
        if (tokenResponse is null)
            return BadRequest("Could not login");
        
        return Ok(tokenResponse);
    }

    [HttpPost("refresh-token")]
    public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto requestDto)
    {
        var result = await _authService.RefreshTokenAsync(requestDto);

        if (result is null || result?.AccessToken is null || result?.RefreshToken is null)
        {
            return BadRequest("Could not refresh token");
        }
        
        return Ok(result);
    }
    
    [HttpGet, Authorize]
    public IActionResult AuthenticatedOnlyEndpoint()
    {
        return Ok("You are authenticated");    
    }
    
    [HttpGet("admin-only"), Authorize(Roles = "Admin")]
    public IActionResult AdminOnlyEndpoint()
    {
        return Ok("You are an admin");    
    }
}