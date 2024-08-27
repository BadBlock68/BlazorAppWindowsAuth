using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace BlazorAppWindowsAuth;

public class CustomAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CustomAuthenticationStateProvider(IHttpContextAccessor httpContextAccessor)
    {
        this._httpContextAccessor = httpContextAccessor;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var identity = _httpContextAccessor.HttpContext.User.Identity;
        var windowsAccountName = identity.Name.Split('\\').Last();

        var ci = identity as ClaimsIdentity;
        var user = new ClaimsPrincipal(identity);

        user.AddIdentity(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Role, "Admin") }));
        user.AddIdentity(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Role, "Manager") }));
        return await Task.FromResult(new AuthenticationState(user));
    }
}
