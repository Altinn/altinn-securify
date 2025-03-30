namespace Altinn.Securify.Models.Dto;

public class SenderDto
{
    public string OrgNo { get; set; } = null!;
    public string ClientId { get; set; } = null!;
    public List<string> Scopes { get; set; } = null!;
}