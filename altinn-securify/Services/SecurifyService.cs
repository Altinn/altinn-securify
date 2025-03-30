using System.Text.Json;
using System.Buffers.Text;
using System.Text;
using Altinn.Securify.Models;
using Altinn.Securify.Services.Interfaces;

namespace Altinn.Securify.Services;

public class SecurifyService : ISecurifyService
{
    private const string CurrentKeyId = "20250102";
    private const string CipherTextPrefix = "as_";

    private readonly IEncryptionService _encryptionService;
    private readonly IKeyResolverService _keyResolverService;
    private readonly IUserService _userService;


    public SecurifyService(IEncryptionService encryptionService, IKeyResolverService keyResolverService, IUserService userService)
    {
        _encryptionService = encryptionService;
        _keyResolverService = keyResolverService;
        _userService = userService;
    }

    public async Task<EncryptionResult> Encrypt(EncryptionRequest request) => await GetEncryptionResult(request);

    public async Task<DecryptionResult> Decrypt(DecryptionRequest request) => await GetDecryptionResult(request);

    private async Task<DecryptionResult> GetDecryptionResult(DecryptionRequest request)
    {
        var securedData = await GetDecodedAndDecryptedData(request);
        var errors = ValidateSecuredData(securedData);

        if (errors.Count > 0)
        {
            return new DecryptionResult
            {
                Errors = errors
            };
        }

        return new DecryptionResult
        {
            Timestamp = securedData!.At,
            User = securedData.By,
            PlainText = securedData.Data
        };
    }

    private async Task<EncryptionResult> GetEncryptionResult(EncryptionRequest request)
    {
        var encodedAndEncryptedData = await GetEncodedAndEncryptedData(request);

        return new EncryptionResult
        {
            CipherText = encodedAndEncryptedData
        };
    }

    private List<string> ValidateSecuredData(EncryptedData? securedData)
    {
        if (securedData is null)
        {
            return ["Unable to decrypt supplied cipher text"];
        }

        var errors = new List<string>();
        if (securedData.Settings.ExpiresAt < DateTimeOffset.UtcNow)
        {
            errors.Add("Secured data has expired");
        }

        var user = _userService.GetUser();
        if (securedData.Settings.RequiresOrgNo != null && !securedData.Settings.RequiresOrgNo.Contains(user.OrgNo))
        {
            errors.Add("The currently authenticated organization number is not allowed to decrypt this data");
        }

        if (securedData.Settings.RequiresClientId != null && !securedData.Settings.RequiresClientId.Contains(user.ClientId))
        {
            errors.Add("The currently authenticated client ID is not allowed to decrypt this data");
        }

        if (securedData.Settings.RequiresScope != null &&
            !securedData.Settings.RequiresScope.All(x => user.Scopes.Contains(x)))
        {
            errors.Add("The currently authenticated scopes are not allowed to decrypt this data");
        }

        return errors;
    }

    private async Task<string> GetEncodedAndEncryptedData(EncryptionRequest request)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(new EncryptedData(request.Settings, DateTimeOffset.Now, _userService.GetUser(), request.PlainText));
        var ciphertext = await _encryptionService.Encrypt(plaintext, CurrentKeyId, _keyResolverService.GetKey);
        return CipherTextPrefix + Base64Url.EncodeToString(ciphertext);
    }

    private async Task<EncryptedData?> GetDecodedAndDecryptedData(DecryptionRequest request)
    {
        var ciphertext = Base64Url.DecodeFromUtf8(Encoding.UTF8.GetBytes(request.CipherText.Substring(CipherTextPrefix.Length)));
        var plaintext = await _encryptionService.Decrypt(ciphertext, _keyResolverService.GetKey);

        return JsonSerializer.Deserialize<EncryptedData>(plaintext);
    }
}