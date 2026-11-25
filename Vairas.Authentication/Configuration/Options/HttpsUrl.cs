namespace Vairas.Authentication.Configuration.Options;

internal static class HttpsUrl
{
    public static bool IsValid(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == "https" && string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment);
}
