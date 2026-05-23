using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using OWSShared.Interfaces;
using Serilog;

namespace OWSShared.Middleware
{
    /// <summary>
    /// Extracts the X-CustomerGUID tenant header on every request and exposes it via
    /// IHeaderCustomerGUID. Optionally verifies an HMAC-SHA256 signature of the request
    /// (timestamp + METHOD + path + sha256(body)) to prevent forgery of the customer
    /// identity. Plain X-CustomerGUID is forgeable — anyone can pick a tenant by typing
    /// its GUID. HMAC binds the request to a shared secret known only to legit clients.
    ///
    /// Rollout strategy (anti-foot-gun): controlled by appsettings "OWSHmac" section.
    ///   - Enabled = false (default): legacy behavior, no signature check.
    ///   - Enabled = true, RequireSignature = false: signed requests are validated,
    ///     unsigned requests pass with a Warning log. Use this phase to deploy the
    ///     middleware backend-side, then update clients, then verify warnings drop to 0.
    ///   - Enabled = true, RequireSignature = true: unsigned or invalid → 401.
    /// </summary>
    public class StoreCustomerGUIDMiddleware : IMiddleware
    {
        // Header names. Keep these in sync with the UE5 client helper (OWSHmacSigning).
        private const string HeaderCustomerGuid = "X-CustomerGUID";
        private const string HeaderTimestamp = "X-Customer-Timestamp";
        private const string HeaderSignature = "X-Customer-Signature";

        // Anti-replay window. ±5 min covers any reasonable client/server clock drift
        // while keeping the replay window short enough to limit damage from a captured
        // request. Overridable per-deployment via OWSHmac:ClockSkewSeconds.
        private const int DefaultClockSkewSeconds = 300;

        private readonly IHeaderCustomerGUID _customerGuid;
        private readonly HmacOptions _hmac;

        public StoreCustomerGUIDMiddleware(IHeaderCustomerGUID customerGuid, IConfiguration configuration)
        {
            _customerGuid = customerGuid;
            _hmac = HmacOptions.FromConfiguration(configuration);
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            // 1) Parse + validate the tenant GUID (unchanged legacy behavior).
            try
            {
                _customerGuid.CustomerGUID = Guid.Parse(context.Request.Headers.FirstOrDefault(x =>
                    string.Equals(x.Key, HeaderCustomerGuid, StringComparison.CurrentCultureIgnoreCase)).Value.ToString());

                if (_customerGuid.CustomerGUID == Guid.Empty)
                {
                    await Reject401(context, "Invalid or missing X-CustomerGUID header");
                    return;
                }
            }
            catch (Exception ex)
            {
                // Debug-level: malformed/missing X-CustomerGUID is a normal client error,
                // not a server fault. Bumping to Error would drown legitimate signal in noise.
                Log.Debug(ex, "StoreCustomerGUID rejected header");
                await Reject401(context, "Invalid or missing X-CustomerGUID header");
                return;
            }

            // 2) Optional HMAC verification. Three modes — see class-level comment.
            if (_hmac.Enabled)
            {
                var verdict = await VerifyHmacAsync(context);
                if (verdict == HmacVerdict.Reject)
                {
                    // Generic error message — never leak which check failed (timestamp vs
                    // signature vs missing). An attacker probing the boundary should learn
                    // nothing about the exact reason for rejection.
                    await Reject401(context, "Request signature invalid or missing");
                    return;
                }
                // verdict == Accept (Strict pass OR Unsigned + RequireSignature=false): continue.
            }

            await next(context);
        }

        // -------------------------------------------------------------------------
        // HMAC verification
        // -------------------------------------------------------------------------

        private enum HmacVerdict { Accept, Reject }

        private async Task<HmacVerdict> VerifyHmacAsync(HttpContext context)
        {
            var timestampHeader = context.Request.Headers[HeaderTimestamp].ToString();
            var signatureHeader = context.Request.Headers[HeaderSignature].ToString();

            // Unsigned request handling.
            if (string.IsNullOrWhiteSpace(timestampHeader) || string.IsNullOrWhiteSpace(signatureHeader))
            {
                if (_hmac.RequireSignature)
                {
                    Log.Warning("HMAC rejected: missing signature headers (path {Path}, IP {IP})",
                        context.Request.Path.Value,
                        context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                    return HmacVerdict.Reject;
                }

                Log.Warning("HMAC opt-in: unsigned request accepted (path {Path}, IP {IP}). " +
                            "Flip OWSHmac:RequireSignature=true once all clients are patched.",
                    context.Request.Path.Value,
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                return HmacVerdict.Accept;
            }

            // Anti-replay: reject timestamps outside the skew window. Done before any
            // crypto work so a flood of stale-timestamp requests can't burn CPU.
            if (!long.TryParse(timestampHeader, out var clientUnix))
            {
                Log.Warning("HMAC rejected: timestamp not an integer (path {Path})", context.Request.Path.Value);
                return HmacVerdict.Reject;
            }
            var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (Math.Abs(nowUnix - clientUnix) > _hmac.ClockSkewSeconds)
            {
                Log.Warning("HMAC rejected: timestamp drift {Drift}s exceeds {Allowed}s (path {Path})",
                    nowUnix - clientUnix, _hmac.ClockSkewSeconds, context.Request.Path.Value);
                return HmacVerdict.Reject;
            }

            // Body must be re-readable by downstream model binders, so buffer it.
            context.Request.EnableBuffering();
            var bodyHashHex = await Sha256HexOfBodyAsync(context.Request);

            // Canonical string: timestamp \n METHOD \n path \n sha256(body)
            // path uses PathBase + Path to match what the client sees (excludes query string,
            // which is fine — query strings are not used for state-changing OWS endpoints).
            var canonical = string.Concat(
                clientUnix.ToString(),
                "\n",
                context.Request.Method.ToUpperInvariant(),
                "\n",
                context.Request.Path.HasValue ? context.Request.Path.Value : "/",
                "\n",
                bodyHashHex);

            var expectedHex = ComputeHmacSha256Hex(_hmac.SecretBytes, canonical);

            // Constant-time comparison: never short-circuit on first byte mismatch, or a
            // timing attacker can recover the signature byte-by-byte. Convert to bytes
            // first so FixedTimeEquals operates on equal-length spans.
            byte[] expectedBytes, actualBytes;
            try
            {
                expectedBytes = Convert.FromHexString(expectedHex);
                actualBytes = Convert.FromHexString(signatureHeader);
            }
            catch (FormatException)
            {
                Log.Warning("HMAC rejected: signature header not valid hex (path {Path})", context.Request.Path.Value);
                return HmacVerdict.Reject;
            }

            if (expectedBytes.Length != actualBytes.Length ||
                !CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes))
            {
                Log.Warning("HMAC rejected: signature mismatch (path {Path}, IP {IP})",
                    context.Request.Path.Value,
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                return HmacVerdict.Reject;
            }

            return HmacVerdict.Accept;
        }

        private static async Task<string> Sha256HexOfBodyAsync(HttpRequest request)
        {
            // Empty body is common (GETs). Use the canonical sha256 of empty input rather
            // than a special-case sentinel so client and server agree without branching.
            if (request.ContentLength == 0)
            {
                using var emptySha = SHA256.Create();
                return BytesToHex(emptySha.ComputeHash(Array.Empty<byte>()));
            }

            using var ms = new MemoryStream();
            await request.Body.CopyToAsync(ms);
            request.Body.Position = 0; // rewind so MVC model binders can read

            using var sha = SHA256.Create();
            return BytesToHex(sha.ComputeHash(ms.ToArray()));
        }

        private static string ComputeHmacSha256Hex(byte[] secret, string canonical)
        {
            using var hmac = new HMACSHA256(secret);
            return BytesToHex(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical)));
        }

        private static string BytesToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        // -------------------------------------------------------------------------
        // Helpers
        // -------------------------------------------------------------------------

        private static async Task Reject401(HttpContext context, string message)
        {
            // ASP.NET Core's HttpResponse has no Clear() (that was classic System.Web).
            // We achieve the same effect by clearing headers + resetting content metadata
            // before writing. Don't touch the body Stream — WriteAsync handles framing.
            // Guard the header clear: throws if anything downstream already started writing
            // the response, in which case the best we can do is set the status code.
            if (!context.Response.HasStarted)
            {
                context.Response.Headers.Clear();
                context.Response.ContentLength = null;
                context.Response.ContentType = "text/plain";
            }
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync(message);
        }

        /// <summary>
        /// HMAC configuration parsed from appsettings "OWSHmac" section. Defensive defaults:
        /// if the section is missing, HMAC is disabled (legacy behavior). If Enabled=true
        /// but Secret is empty, we still disable + log an error rather than fail open with
        /// an empty key — better to be loud about misconfiguration.
        /// </summary>
        private sealed class HmacOptions
        {
            public bool Enabled { get; private init; }
            public bool RequireSignature { get; private init; }
            public int ClockSkewSeconds { get; private init; }
            public byte[] SecretBytes { get; private init; } = Array.Empty<byte>();

            public static HmacOptions FromConfiguration(IConfiguration config)
            {
                var section = config.GetSection("OWSHmac");
                var enabled = section.GetValue<bool?>("Enabled") ?? false;
                var requireSig = section.GetValue<bool?>("RequireSignature") ?? false;
                var skew = section.GetValue<int?>("ClockSkewSeconds") ?? DefaultClockSkewSeconds;
                var secret = section.GetValue<string>("Secret") ?? string.Empty;

                if (enabled && string.IsNullOrEmpty(secret))
                {
                    Log.Error("OWSHmac:Enabled=true but OWSHmac:Secret is empty. HMAC check disabled. " +
                              "Set OWSHmac:Secret to a 32+ byte random string in appsettings or env var.");
                    enabled = false;
                }

                return new HmacOptions
                {
                    Enabled = enabled,
                    RequireSignature = requireSig,
                    ClockSkewSeconds = Math.Max(1, skew),
                    SecretBytes = Encoding.UTF8.GetBytes(secret),
                };
            }
        }
    }
}
