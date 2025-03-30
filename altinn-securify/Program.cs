using System.Net;
using Altinn.Securify.Authentication;
using Altinn.Securify.Authorization;
using Altinn.Securify.Configuration;
using Altinn.Securify.Models.Dto;
using Altinn.Securify.Services;
using Altinn.Securify.Services.Interfaces;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<SecurifyConfig>(builder.Configuration.GetSection(nameof(SecurifyConfig)));
builder.Services
    .ConfigureOptions<AuthorizationOptionsSetup>()
    .AddSingleton<IKeyResolverService, SettingsBasedKeyResolverService>()
    .AddSingleton<IEncryptionService, AesGcmEncryptionService>()
    .AddSingleton<ISecurifyService, SecurifyService>()
    .AddSingleton<IUserService, UserService>()
    .AddHttpContextAccessor()
    .AddOpenApi()
    .AddSecurifyAuthentication(builder.Configuration)
    .AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection()
    .UseJwtSchemeSelector()
    .UseAuthentication()
    .UseAuthorization()
    .UseMiddleware<ExceptionHandlingMiddleware>();


app.MapPost("/encrypt", async (IOptions<SecurifyConfig> securifyConfig, ISecurifyService securifyService, EncryptionRequestDto requestDto) =>
{
    var errors = requestDto.Validate(securifyConfig.Value);
    if (errors.Count > 0)
    {
        return Results.Problem(
            title: "Encryption error",
            statusCode: (int) HttpStatusCode.BadRequest,
            detail: string.Join(", ", errors));
    }

    var encryptionRequest = requestDto.ToEncryptionRequest(securifyConfig.Value);
    var encryptionResult = await securifyService.Encrypt(encryptionRequest);

    return Results.Ok(encryptionResult.ToEncryptionResultDto());
}).RequireAuthorization();

app.MapPost("/decrypt", async (ISecurifyService securifyService, DecryptionRequestDto requestDto) =>
{
    var decryptionRequest = requestDto.ToDecryptionRequest();
    var decryptionResult = await securifyService.Decrypt(decryptionRequest);

    if (decryptionResult.Errors.Count > 0)
    {
        return Results.Problem(
            title: "Decryption error",
            statusCode: (int) HttpStatusCode.BadRequest,
            detail: string.Join(", ", decryptionResult.Errors));
    }

    return Results.Ok(decryptionResult.ToDecryptionResultDto());
}).RequireAuthorization();

await app.RunAsync();
