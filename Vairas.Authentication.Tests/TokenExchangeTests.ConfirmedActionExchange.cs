using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.ConfirmedActions;
namespace Vairas.Authentication.Tests;

public sealed partial class TokenExchangeTests
{
    private LessonActionBinding Binding(string kind="Booking") => new(school,Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),identity,Guid.NewGuid(),session,kind,new('a',64),new('b',64));
    [TestCase("Booking")][TestCase("Rescheduling")]
    public async Task Confirmed_action_exchange_preserves_exact_binding_across_only_two_hops(string kind)
    {
        options.Delegation.ConfirmedLessonActionsEnabled=true;var binding=Binding(kind);var json=JsonSerializer.Serialize(binding,LessonActions.Json);
        var first=await exchange.IssueAsync("chat-backend",Secret,User(),GrantType,null,options.Delegation.McpResource,LessonActions.Scope(kind),school.ToString(),default,json);
        var second=await exchange.IssueAsync("mcp-server",Secret,first.AccessToken,GrantType,null,options.Delegation.Resources["scheduling"],LessonActions.Scope(kind),school.ToString(),default);
        var jwt=new JwtSecurityTokenHandler().ReadJwtToken(second.AccessToken);
        Assert.That(jwt.Audiences,Is.EqualTo(new[]{"vairas-scheduling"}));Assert.That(jwt.Claims.Single(c=>c.Type==LessonActions.Claim).Value,Is.EqualTo(json));
        Assert.That(jwt.Claims.Single(c=>c.Type=="vairas_delegation").Value,Is.EqualTo(LessonActions.Profile));Assert.That(second.ExpiresIn,Is.InRange(1,30));
        Business.ThrowsBusinessAsync(()=>exchange.IssueAsync("mcp-server",Secret,second.AccessToken,GrantType,null,options.Delegation.Resources["scheduling"],LessonActions.Scope(kind),school.ToString(),default));
    }
    [TestCase("disabled")][TestCase("identity")][TestCase("session")][TestCase("school")][TestCase("kind")][TestCase("digest")][TestCase("scope")]
    public void Invalid_execution_binding_cannot_be_minted(string variant)
    {
        options.Delegation.ConfirmedLessonActionsEnabled=true;var binding=Binding();var scope=LessonActions.Scope(binding.Kind);
        switch(variant)
        {
            case "disabled":options.Delegation.ConfirmedLessonActionsEnabled=false;break;
            case "identity":binding=binding with {IdentityId=Guid.NewGuid()};break;
            case "session":binding=binding with {SessionId=Guid.NewGuid()};break;
            case "school":binding=binding with {SchoolId=Guid.NewGuid()};break;
            case "kind":binding=binding with {Kind="Cancel"};break;
            case "digest":binding=binding with {CommandDigest="bad"};break;
            case "scope":scope="mcp.create_lesson_booking mcp.get_my_lessons";break;
        }
        Business.ThrowsBusinessAsync(()=>exchange.IssueAsync("chat-backend",Secret,User(),GrantType,null,options.Delegation.McpResource,scope,school.ToString(),default,JsonSerializer.Serialize(binding,LessonActions.Json)));
    }
    [Test]
    public async Task Read_preview_token_cannot_be_upgraded_or_execution_token_sent_to_another_owner()
    {
        options.Delegation.ConfirmedLessonActionsEnabled=true;
        var preview=await First();
        Business.ThrowsBusinessAsync(()=>exchange.IssueAsync("mcp-server",Secret,preview.AccessToken,GrantType,null,options.Delegation.Resources["scheduling"],"mcp.create_lesson_booking",school.ToString(),default));
        var first=await exchange.IssueAsync("chat-backend",Secret,User(),GrantType,null,options.Delegation.McpResource,"mcp.create_lesson_booking",school.ToString(),default,JsonSerializer.Serialize(Binding(),LessonActions.Json));
        Business.ThrowsBusinessAsync(()=>exchange.IssueAsync("mcp-server",Secret,first.AccessToken,GrantType,null,options.Delegation.Resources["school-management"],"mcp.create_lesson_booking",school.ToString(),default));
        Business.ThrowsBusinessAsync(()=>exchange.IssueAsync("mcp-server",Secret,first.AccessToken,GrantType,null,options.Delegation.Resources["scheduling"],"mcp.reschedule_lesson_booking",school.ToString(),default));
    }
}
