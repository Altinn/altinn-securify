
using System.Security.Claims;
using System.Text.Json;
using Altinn.Securify.Models;
using Altinn.Securify.Services.Interfaces;

namespace Altinn.Securify.Services;

public class UserService : IUserService
{
    private const string AuthorityClaim = "authority";
    private const string AuthorityValue = "iso6523-actorid-upis";
    private const string IdClaim = "ID";
    private const char IdDelimiter = ':';
    private const string IdPrefix = "0192";

    private readonly IHttpContextAccessor _httpContextAccessor;

    public UserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public User GetUser()
    {
        ArgumentNullException.ThrowIfNull(_httpContextAccessor.HttpContext, nameof(_httpContextAccessor.HttpContext));
        var claims = _httpContextAccessor.HttpContext.User.Claims.ToList();

        return new User(
            GetOrganizationNumber(claims),
            GetClientId(claims),
            GetScopes(claims));
    }

    private static List<string> GetScopes(IEnumerable<Claim> claims)
    {
        var claim = claims.FirstOrDefault(c => c.Type == "scope");
        ArgumentNullException.ThrowIfNull(claim, nameof(claim));
        return claim.Value.Split(' ').ToList();
    }

    private static string GetClientId(IEnumerable<Claim> claims)
    {
        var claim = claims.FirstOrDefault(c => c.Type == "client_id");
        ArgumentNullException.ThrowIfNull(claim, nameof(claim));
        return claim.Value;
    }

    private static string GetOrganizationNumber(IEnumerable<Claim> claims)
    {
        var claim = claims.FirstOrDefault(c => c.Type == "consumer");
        ArgumentNullException.ThrowIfNull(claim, nameof(claim));

        var consumerClaimJson = JsonSerializer.Deserialize<Dictionary<string, string>>(claim.Value);
        ArgumentNullException.ThrowIfNull(consumerClaimJson, nameof(consumerClaimJson));

        if (!consumerClaimJson.TryGetValue(AuthorityClaim, out var authority) ||
            !string.Equals(authority, AuthorityValue, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(nameof(AuthorityClaim));
        }

        if (!consumerClaimJson.TryGetValue(IdClaim, out var id))
        {
            throw new InvalidOperationException(nameof(IdClaim));
        }

        var orgNumber = id.Split(IdDelimiter) switch
        {
            [IdPrefix, var orgNo] => orgNo,
            _ => throw new InvalidOperationException(nameof(IdDelimiter))
        };

        return orgNumber;
    }
}