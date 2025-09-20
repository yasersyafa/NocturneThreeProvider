namespace NocturneThreeProvider.Helpers;

public static class HttpContextExtension
{
    public static string GetIpAddress(this HttpContext context)
    {
        // Cek X-Forwarded-For header (biasanya dipakai kalau app di belakang proxy / load balancer)
        var forwardedHeader = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedHeader))
        {
            return forwardedHeader.Split(',').First().Trim();
        }

        // Ambil langsung dari koneksi
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}