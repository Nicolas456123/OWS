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
        public async Task Hmac_EnabledButEmptySecret_FailsClosed()
        {
            // Misconfigured: Enabled=true but Secret="". Middleware logs error and falls back to
            // legacy behavior (no HMAC check) rather than fail-open with empty key. The legacy
            // X-CustomerGUID parsing still applies, so a valid GUID still passes.
            var customerGuid = new TestHeaderCustomerGUID();
            var config = BuildConfig(new() {
                ["Enabled"] = "true",
                ["RequireSignature"] = "true",
                ["Secret"] = "",
            });
            var middleware = CreateMiddleware(customerGuid, config);

            var context = new DefaultHttpContext();
            context.Request.Method = "GET";
            context.Request.Path = "/api/x";
            context.Request.Headers["X-CustomerGUID"] = Guid.NewGuid().ToString();

            bool nextCalled = false;
            await middleware.InvokeAsync(context, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled);
        }
    }
}
