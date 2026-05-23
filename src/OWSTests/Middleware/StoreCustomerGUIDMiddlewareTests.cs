using Xunit;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using OWSShared.Middleware;
using OWSShared.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OWSTests.Middleware
{
    /// <summary>
    /// Simple implementation of IHeaderCustomerGUID for testing purposes.
    /// </summary>
    internal class TestHeaderCustomerGUID : IHeaderCustomerGUID
    {
        public Guid CustomerGUID { get; set; }
    }

    public class StoreCustomerGUIDMiddlewareTests
    {
        // Constant test secret. Real deployments rotate this per-environment via
        // appsettings.{env}.json or OWSHMAC__SECRET env var.
        private const string TestSecret = "test-shared-secret-32-bytes-min-XXXXXX";

        // -------------------------------------------------------------------------
        // Helpers
        // -------------------------------------------------------------------------

        private static IConfiguration BuildConfig(Dictionary<string, string?>? hmac = null)
        {
            // Default: HMAC disabled. Tests opt-in by passing a dict.
            var dict = new Dictionary<string, string?>();
            if (hmac != null)
            {
                foreach (var kv in hmac) dict["OWSHmac:" + kv.Key] = kv.Value;
            }
            return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
        }

        private static StoreCustomerGUIDMiddleware CreateMiddleware(
            IHeaderCustomerGUID customerGuid,
            IConfiguration? config = null)
        {
            return new StoreCustomerGUIDMiddleware(customerGuid, config ?? BuildConfig());
        }

        private static string Hex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private static string ComputeSignature(string secret, long timestamp, string method, string path, byte[] body)
        {
            using var sha = SHA256.Create();
            var bodyHash = Hex(sha.ComputeHash(body));
            var canonical = $"{timestamp}\n{method.ToUpperInvariant()}\n{path}\n{bodyHash}";
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            return Hex(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical)));
        }

        // -------------------------------------------------------------------------
        // Legacy tests (HMAC disabled) — preserved from original suite
        // -------------------------------------------------------------------------

        [Fact]
        public async Task MissingHeader_Returns401()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var middleware = CreateMiddleware(customerGuid);

            var context = new DefaultHttpContext();
            context.Response.Body = new MemoryStream();

            await middleware.InvokeAsync(context, (ctx) => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task InvalidGUID_Returns401()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var middleware = CreateMiddleware(customerGuid);

            var context = new DefaultHttpContext();
            context.Request.Headers["X-CustomerGUID"] = "not-a-valid-guid";
            context.Response.Body = new MemoryStream();

            await middleware.InvokeAsync(context, (ctx) => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task EmptyGUID_Returns401()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var middleware = CreateMiddleware(customerGuid);

            var context = new DefaultHttpContext();
            context.Request.Headers["X-CustomerGUID"] = Guid.Empty.ToString();
            context.Response.Body = new MemoryStream();

            await middleware.InvokeAsync(context, (ctx) => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task ValidGUID_PassesThrough()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var middleware = CreateMiddleware(customerGuid);

            bool nextCalled = false;
            var context = new DefaultHttpContext();
            var validGuid = Guid.NewGuid();
            context.Request.Headers["X-CustomerGUID"] = validGuid.ToString();

            await middleware.InvokeAsync(context, (ctx) => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled);
            Assert.Equal(validGuid, customerGuid.CustomerGUID);
        }

        [Fact]
        public async Task ValidGUID_StoresCorrectGUID()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var middleware = CreateMiddleware(customerGuid);

            var context = new DefaultHttpContext();
            var expectedGuid = Guid.NewGuid();
            context.Request.Headers["X-CustomerGUID"] = expectedGuid.ToString();

            await middleware.InvokeAsync(context, (ctx) => Task.CompletedTask);

            Assert.Equal(expectedGuid, customerGuid.CustomerGUID);
        }

        // -------------------------------------------------------------------------
        // HMAC tests
        // -------------------------------------------------------------------------

        [Fact]
        public async Task Hmac_ValidSignature_PassesThrough()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = TestSecret,
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.Path = "/api/users/loginandcreatesession";
            var body = Encoding.UTF8.GetBytes("{\"Email\":\"a@b.c\"}");
            context.Request.Body = new MemoryStream(body);
            context.Request.ContentLength = body.Length;
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();

            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            context.Request.Headers["X-Customer-Timestamp"] = ts.ToString();
            context.Request.Headers["X-Customer-Signature"] =
                ComputeSignature(TestSecret, ts, "POST", "/api/users/loginandcreatesession", body);

            bool nextCalled = false;
            await middleware.InvokeAsync(context, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled);
            Assert.NotEqual(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task Hmac_InvalidSignature_Returns401()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = TestSecret,
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.Path = "/api/x";
            context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{}"));
            context.Request.ContentLength = 2;
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();
            context.Request.Headers["X-Customer-Timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            // Signature is the right length but wrong content — caught by FixedTimeEquals.
            context.Request.Headers["X-Customer-Signature"] = new string('a', 64);
            context.Response.Body = new MemoryStream();

            await middleware.InvokeAsync(context, _ => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task Hmac_TimestampTooOld_Returns401()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = TestSecret,
                ["ClockSkewSeconds"] = "300",
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.Path = "/api/x";
            var body = Encoding.UTF8.GetBytes("{}");
            context.Request.Body = new MemoryStream(body);
            context.Request.ContentLength = body.Length;
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();

            // 10 minutes in the past — well past the 5-min skew window.
            var oldTs = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds();
            context.Request.Headers["X-Customer-Timestamp"] = oldTs.ToString();
            // Signature is otherwise valid: ensures we reject on timestamp alone, not signature mismatch.
            context.Request.Headers["X-Customer-Signature"] =
                ComputeSignature(TestSecret, oldTs, "POST", "/api/x", body);
            context.Response.Body = new MemoryStream();

            await middleware.InvokeAsync(context, _ => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task Hmac_TimestampInFuture_Returns401()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = TestSecret,
                ["ClockSkewSeconds"] = "300",
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.Path = "/api/x";
            var body = Encoding.UTF8.GetBytes("{}");
            context.Request.Body = new MemoryStream(body);
            context.Request.ContentLength = body.Length;
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();

            var futureTs = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();
            context.Request.Headers["X-Customer-Timestamp"] = futureTs.ToString();
            context.Request.Headers["X-Customer-Signature"] =
                ComputeSignature(TestSecret, futureTs, "POST", "/api/x", body);
            context.Response.Body = new MemoryStream();

            await middleware.InvokeAsync(context, _ => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task Hmac_OptInMode_UnsignedAccepted()
        {
            // Enabled but RequireSignature=false: unsigned requests pass with warning log.
            // This is the rollout phase used to deploy the backend before clients are updated.
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "false",
                ["Secret"] = TestSecret,
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.Path = "/api/x";
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();
            // No timestamp, no signature.

            bool nextCalled = false;
            await middleware.InvokeAsync(context, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled);
            Assert.NotEqual(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task Hmac_StrictMode_UnsignedReturns401()
        {
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = TestSecret,
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.Path = "/api/x";
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();
            context.Response.Body = new MemoryStream();
            // No signature headers — strict mode rejects.

            await middleware.InvokeAsync(context, _ => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
        }

        [Fact]
        public void Hmac_EnabledButEmptySecret_ThrowsAtConstruction()
        {
            // Misconfigured: Enabled=true but Secret="". The old behavior (disable HMAC
            // silently + Log.Error once) was fail-OPEN: after log rotation the operator
            // had no signal HMAC was off. New behavior: throw at middleware construction
            // so the service refuses to start until either the secret is set OR the
            // operator explicitly sets Enabled=false to opt out.
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = "",
            });

            var ex = Assert.Throws<InvalidOperationException>(
                () => CreateMiddleware(customerGuid, config));
            Assert.Contains("OWSHmac:Secret", ex.Message);
        }

        [Fact]
        public async Task Hmac_BodyExceedsMax_Returns401()
        {
            // DoS guard: attacker sends a 3 MB body when MaxBodyBytes=1 MB. Middleware
            // aborts the read mid-stream before the full body is buffered, returns 401.
            // Rejection is generic (no 413) so an attacker probing can't distinguish
            // "too big" from "bad signature".
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = TestSecret,
                ["MaxBodyBytes"] = "1048576", // 1 MB
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.Path = "/api/x";
            // 3 MB of zeros — well past the 1 MB cap.
            var body = new byte[3 * 1024 * 1024];
            context.Request.Body = new MemoryStream(body);
            context.Request.ContentLength = body.Length;
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            context.Request.Headers["X-Customer-Timestamp"] = ts.ToString();
            // Signature would be valid for the body, but cap check fires first.
            context.Request.Headers["X-Customer-Signature"] =
                ComputeSignature(TestSecret, ts, "POST", "/api/x", body);
            context.Response.Body = new MemoryStream();

            await middleware.InvokeAsync(context, _ => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task Hmac_RejectedRequest_DoesNotLeakTenantGUID()
        {
            // Audit-log hardening: on HMAC rejection, the scoped IHeaderCustomerGUID
            // must NOT carry the attacker-supplied GUID — otherwise downstream Serilog
            // enrichers or exception filters would attribute the probe to whichever
            // tenant the attacker named (logged "tenant <victim> failed HMAC" when the
            // attacker just made up the GUID). After fix #8, the GUID is only committed
            // to the scope after all checks pass.
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = TestSecret,
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var attackerGuid = Guid.NewGuid();
            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.Path = "/api/x";
            context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{}"));
            context.Request.ContentLength = 2;
            context.Request.Headers["X-CustomerGUID"] = attackerGuid.ToString();
            context.Request.Headers["X-Customer-Timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            context.Request.Headers["X-Customer-Signature"] = new string('a', 64); // wrong
            context.Response.Body = new MemoryStream();

            await middleware.InvokeAsync(context, _ => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
            Assert.Equal(Guid.Empty, customerGuid.CustomerGUID);
            Assert.NotEqual(attackerGuid, customerGuid.CustomerGUID);
        }

        [Theory]
        [InlineData("-9223372036854775808")] // long.MinValue
        [InlineData("9223372036854775807")]  // long.MaxValue
        [InlineData("-1")]                    // negative — Unix time can't be < 0
        public async Task Hmac_ExtremeTimestamp_Returns401NotCrash(string timestampStr)
        {
            // Math.Abs(long.MinValue) throws OverflowException. Before fix #12, an
            // attacker sending X-Customer-Timestamp: -9223372036854775808 crashed
            // the request with 500 (bypassing the standard rejection log). Now the
            // bounds-check rejects cleanly with 401 before any arithmetic.
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = TestSecret,
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.Path = "/api/x";
            context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{}"));
            context.Request.ContentLength = 2;
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();
            context.Request.Headers["X-Customer-Timestamp"] = timestampStr;
            context.Request.Headers["X-Customer-Signature"] = new string('a', 64);
            context.Response.Body = new MemoryStream();

            // Must not throw; must return clean 401.
            await middleware.InvokeAsync(context, _ => Task.CompletedTask);

            Assert.Equal(401, context.Response.StatusCode);
        }

        [Fact]
        public async Task Hmac_PathBase_IncludedInCanonical()
        {
            // Reverse-proxy scenario: OWS mounted at /owspublic. Server's Request.Path
            // strips the base; without PathBase included, server reconstructs "/api/x"
            // while client signs "/owspublic/api/x" → every request 401. This test signs
            // with the full prefixed path and verifies the middleware accepts it.
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = TestSecret,
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "POST";
            context.Request.PathBase = "/owspublic";
            context.Request.Path = "/api/x";
            var body = Encoding.UTF8.GetBytes("{}");
            context.Request.Body = new MemoryStream(body);
            context.Request.ContentLength = body.Length;
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            context.Request.Headers["X-Customer-Timestamp"] = ts.ToString();
            // Client signs the full URL path as it sees it (/owspublic/api/x).
            context.Request.Headers["X-Customer-Signature"] =
                ComputeSignature(TestSecret, ts, "POST", "/owspublic/api/x", body);

            bool nextCalled = false;
            await middleware.InvokeAsync(context, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled);
            Assert.NotEqual(401, context.Response.StatusCode);
        }
    }
}
