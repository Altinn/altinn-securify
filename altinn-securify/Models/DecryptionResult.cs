using System.Text.Json;
using Altinn.Securify.Models.Dto;

namespace Altinn.Securify.Models;

public class DecryptionResult
{
    public DateTimeOffset Timestamp { get; set; }
    public User User { get; set; } = null!;
    public JsonElement PlainText { get; set; }
    public List<string> Errors { get; set; } = new();

    public DecryptionResultDto ToDecryptionResultDto()
    {
        return new DecryptionResultDto
        {
            At = Timestamp,
            By =  User.ToSenderDto(),
            PlainText = PlainText
        };
    }
}