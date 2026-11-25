using NUnit.Framework;
using Vairas.Authentication.Business;
using Vairas.Authentication.Domain;
using Vairas.Authentication.Security;

namespace Vairas.Authentication.Tests;

[TestFixture, Category("Unit")]
public sealed class PolicyTests
{
    [TestCase(null), TestCase(""), TestCase("missing-at"), TestCase("Display <a@example.test>"), TestCase("a\n@example.test"), TestCase("ü@example.test")]
    public void RejectsInvalidCredentialEmail(string? value) => Business.ThrowsBusiness(() => AuthPolicy.Email(value));
    [Test] public void NormalizesLoginEmailOnly() => Assert.That(AuthPolicy.Email("  A@Example.Test  "), Is.EqualTo("a@example.test"));
    [TestCase(null), TestCase(""), TestCase("too short")]
    public void RejectsShortRegistrationPasswords(string? value) => Business.ThrowsBusiness(() => AuthPolicy.Password(value, true));
    [Test] public void AcceptsExactUnicodeAndSpacesWithoutTruncation() => Assert.DoesNotThrow(() => AuthPolicy.Password("  пароль with spaces  ", true));
    [Test] public void RejectsOversizedPasswords() => Business.ThrowsBusiness(() => AuthPolicy.Password(new string('x', 129), false));
    [TestCase(null), TestCase(""), TestCase("short"), TestCase("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")]
    public void RejectsMalformedOpaqueCredentials(string? value) => Business.ThrowsBusiness(() => AuthPolicy.Secret(value));
    [Test]
    public void GeneratesIndependentOpaqueCredentialsAndStableDigests()
    {
        var a = AuthPolicy.RandomSecret(); var b = AuthPolicy.RandomSecret();
        Assert.That(a.Length, Is.EqualTo(43)); Assert.That(a, Is.Not.EqualTo(b));
        Assert.DoesNotThrow(() => AuthPolicy.Secret(a));
        Assert.That(AuthPolicy.EqualDigest(AuthPolicy.Digest(a), AuthPolicy.Digest(a)), Is.True);
        Assert.That(AuthPolicy.EqualDigest(AuthPolicy.Digest(a), AuthPolicy.Digest(b)), Is.False);
        Assert.That(AuthPolicy.EqualDigest("a", "bb"), Is.False);
    }
    [Test]
    public void AccountThrottlingIsBoundToOperationAndExpires()
    {
        var clock = new MutableClock();
        using var throttle = new AccountThrottle(clock);
        for (var i = 0; i < 3; i++) throttle.Check("same@example.test", "challenge");
        Assert.That(Business.ThrowsBusiness(() => throttle.Check("same@example.test", "challenge")).HttpStatus(), Is.EqualTo(429));
        Assert.DoesNotThrow(() => throttle.Check("same@example.test", "login"));
        Assert.DoesNotThrow(() => throttle.Check("different@example.test", "challenge"));
        clock.Value = clock.Value.AddMinutes(16);
        Assert.DoesNotThrow(() => throttle.Check("same@example.test", "challenge"));
    }
    [Test]
    public void PasswordsUseSaltedArgon2idAndPreserveExactInput()
    {
        using var hasher = new PasswordHasher();
        var first = hasher.Hash(" password with spaces ");
        var second = hasher.Hash(" password with spaces ");
        Assert.That(first, Does.StartWith("$argon2id$").And.Contain("m=65536,t=3,p=1"));
        Assert.That(second, Is.Not.EqualTo(first));
        Assert.That(hasher.Verify(first, " password with spaces "), Is.True);
        Assert.That(hasher.Verify(first, "password with spaces"), Is.False);
        Assert.That(hasher.Verify("not-an-encoded-hash", "password"), Is.False);
        Assert.DoesNotThrow(() => hasher.DummyVerify("unknown"));
    }
    [Test]
    public void AdmissionRequiresEnabledIdentityExactOwnershipAndUnrevokedLifetime()
    {
        var now = DateTimeOffset.UtcNow;
        var i = new Identity { IdentityId = Guid.NewGuid() };
        var s = new AuthSession { IdentityId = i.IdentityId, ExpiresAt = now.AddMinutes(1) };
        Assert.That(AuthPolicy.Active(i, s, now), Is.True);
        s.IdentityId = Guid.NewGuid(); Assert.That(AuthPolicy.Active(i, s, now), Is.False);
        s.IdentityId = i.IdentityId; s.RevokedAt = now; Assert.That(AuthPolicy.Active(i, s, now), Is.False);
        s.RevokedAt = null; s.ExpiresAt = now; Assert.That(AuthPolicy.Active(i, s, now), Is.False);
        s.ExpiresAt = now.AddMinutes(1); i.SecurityState = "Disabled"; Assert.That(AuthPolicy.Active(i, s, now), Is.False);
        Assert.That(AuthPolicy.Active(null, s, now), Is.False);
        Assert.That(AuthPolicy.Active(i, null, now), Is.False);
    }
    private sealed class MutableClock : TimeProvider
    {
        public DateTimeOffset Value { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Value;
    }
}
