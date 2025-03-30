using Altinn.Securify.Models.Dto;

namespace Altinn.Securify.Models;

public record User(string OrgNo, string ClientId, List<string> Scopes)
{
    public SenderDto ToSenderDto()
    {
        return new SenderDto
        {
            OrgNo = OrgNo,
            ClientId = ClientId,
            Scopes = Scopes
        };
    }
}