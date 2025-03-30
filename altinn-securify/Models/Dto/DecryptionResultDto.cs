using System.Text.Json;

namespace Altinn.Securify.Models.Dto;

public class DecryptionResultDto
{
    public DateTimeOffset At { get; set; }
    public SenderDto By { get; set; } = new();
    public JsonElement PlainText { get; set; } = new();
}
