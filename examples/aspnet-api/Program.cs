using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

const string corsPolicyName = "Spa";
const string apiReadPolicyName = "ApiRead";
const string adminReadPolicyName = "AdminRead";

var builder = WebApplication.CreateBuilder(args);

var authority = RequireConfiguration(builder.Configuration, "Oidc:Authority");
var audience = RequireConfiguration(builder.Configuration, "Oidc:Audience");
var corsOrigin = RequireConfiguration(builder.Configuration, "Cors:Origin");

var authorityUri = ValidateAuthority(authority, builder.Environment.IsDevelopment());
ValidateOrigin(corsOrigin, builder.Environment.IsDevelopment());

builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.Audience = audience;
        options.MapInboundClaims = false;
        options.IncludeErrorDetails = builder.Environment.IsDevelopment();
        options.RequireHttpsMetadata = authorityUri.Scheme == Uri.UriSchemeHttps;
        options.RefreshOnIssuerKeyNotFound = true;

        if (builder.Environment.IsDevelopment())
        {
            options.RefreshInterval = TimeSpan.FromSeconds(1);
        }

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "name",
            RoleClaimType = "role"
        };

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                var principal = context.Principal;
                var hasJti = principal?.Claims.Any(claim =>
                    claim.Type == "jti" && !string.IsNullOrWhiteSpace(claim.Value)) == true;
                var hasScope = principal?.Claims
                    .Where(claim => claim.Type == "scope")
                    .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    .Any() == true;
                var hasAuthorizedParty = principal?.Claims.Any(claim => claim.Type == "azp") == true;

                if (!hasJti || !hasScope || hasAuthorizedParty)
                {
                    context.Fail("An OAuth access token is required.");
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(apiReadPolicyName, policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("permission", "api.read");
    });

    options.AddPolicy(adminReadPolicyName, policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("permission", "api.read");
        policy.RequireRole("admin");
    });
});

builder.Services.AddCors(options =>
{
    options.AddPolicy(corsPolicyName, policy =>
    {
        policy
            .WithOrigins(corsOrigin)
            .WithMethods("GET")
            .WithHeaders("Authorization", "Content-Type");
    });
});

var app = builder.Build();

app.UseCors(corsPolicyName);
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/public", () => Results.Ok(new
{
    message = "Hoocloak API is running."
}));

app.MapGet("/api/profile", (ClaimsPrincipal principal) => Results.Ok(new
{
    sub = ClaimValue(principal, "sub"),
    name = ClaimValue(principal, "name"),
    roles = ClaimValues(principal, "role"),
    permissions = ClaimValues(principal, "permission")
})).RequireAuthorization(apiReadPolicyName);

app.MapGet("/api/admin", (ClaimsPrincipal principal) => Results.Ok(new
{
    message = "Admin access granted.",
    sub = ClaimValue(principal, "sub")
})).RequireAuthorization(adminReadPolicyName);

app.Run();

static string RequireConfiguration(IConfiguration configuration, string key)
{
    var value = configuration[key];
    return string.IsNullOrWhiteSpace(value)
        ? throw new InvalidOperationException($"Configuration value '{key}' is required.")
        : value;
}

static Uri ValidateAuthority(string authority, bool isDevelopment)
{
    if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri)
        || !string.IsNullOrEmpty(uri.UserInfo)
        || !string.IsNullOrEmpty(uri.Query)
        || !string.IsNullOrEmpty(uri.Fragment))
    {
        throw new InvalidOperationException("Oidc:Authority must be an absolute URL without credentials, query, or fragment.");
    }

    if (uri.Scheme == Uri.UriSchemeHttps)
    {
        return uri;
    }

    if (uri.Scheme != Uri.UriSchemeHttp || !isDevelopment || !IsLocalHost(uri.Host))
    {
        throw new InvalidOperationException(
            "Oidc:Authority must use HTTPS unless Development uses a loopback, localhost, or .localhost host.");
    }

    return uri;
}

static void ValidateOrigin(string origin, bool isDevelopment)
{
    if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri)
        || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        || !string.IsNullOrEmpty(uri.UserInfo)
        || !string.IsNullOrEmpty(uri.Query)
        || !string.IsNullOrEmpty(uri.Fragment)
        || !string.Equals(origin, uri.GetLeftPart(UriPartial.Authority), StringComparison.Ordinal))
    {
        throw new InvalidOperationException("Cors:Origin must be an absolute HTTP(S) origin without credentials, path, query, or fragment.");
    }

    if (uri.Scheme == Uri.UriSchemeHttp && (!isDevelopment || !IsLocalHost(uri.Host)))
    {
        throw new InvalidOperationException(
            "Cors:Origin must use HTTPS unless Development uses a loopback, localhost, or .localhost host.");
    }
}

static bool IsLocalHost(string host)
{
    return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
        || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
        || (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address));
}

static string? ClaimValue(ClaimsPrincipal principal, string claimType)
{
    return principal.FindFirst(claimType)?.Value;
}

static string[] ClaimValues(ClaimsPrincipal principal, string claimType)
{
    return principal.FindAll(claimType)
        .Select(claim => claim.Value)
        .Distinct(StringComparer.Ordinal)
        .ToArray();
}
