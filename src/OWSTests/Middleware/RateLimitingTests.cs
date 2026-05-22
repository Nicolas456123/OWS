using Xunit;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using OWSShared.Middleware;
using System.IO;
using System.Net;
using System.Threading.Tasks;

namespace OWSTests.Middleware
{
    public class RateLimitingTests
    {
        private static DefaultHttpContext NewContext(string ip, string path = null)
        {
            var ctx = new DefaultHttpContext();
            ctx.Connection.RemoteIpAddress = IPAddress.Parse(ip);
            ctx.Response.Body = new MemoryStream();
            if (path != null)
            {
                ctx.Request.Path = new PathString(path);
            }
            return ctx;
        }

        [Fact]
        public async Task RateLimiting_UnderLimit_PassesThrough()
        {
            var cache = new MemoryCache(new MemoryCacheOptions());
            var middleware = new RateLimitingMiddleware(
                (ctx) => Task.CompletedTask, cache);

            var context = NewContext("127.0.0.1");

            await middleware.InvokeAsync(context);

            Assert.Equal(200, context.Response.StatusCode);
        }

        [Fact]
        public async Task RateLimiting_OverDefaultLimit_Returns429()
        {
            var cache = new MemoryCache(new MemoryCacheOptions());
            var middleware = new RateLimitingMiddleware(
                (ctx) => Task.CompletedTask, cache);

            DefaultHttpContext context = null;

            // Exhaust the default quota (60 req/min on a non-sensitive path)
            for (int i = 0; i < RateLimitingMiddleware.DefaultMaxRequestsPerMinute + 1; i++)
            {
                context = NewContext("127.0.0.1");
                await middleware.InvokeAsync(context);
            }

            Assert.Equal(429, context.Response.StatusCode);
        }

        [Fact]
        public async Task RateLimiting_DifferentIPs_IndependentLimits()
        {
            var cache = new MemoryCache(new MemoryCacheOptions());
            var middleware = new RateLimitingMiddleware(
                (ctx) => Task.CompletedTask, cache);

            // Exhaust limit for IP 1
            for (int i = 0; i < RateLimitingMiddleware.DefaultMaxRequestsPerMinute + 1; i++)
            {
                await middleware.InvokeAsync(NewContext("10.0.0.1"));
            }

            // IP 2 should still work
            var context2 = NewContext("10.0.0.2");
            await middleware.InvokeAsync(context2);

            Assert.Equal(200, context2.Response.StatusCode);
        }

        [Fact]
        public async Task RateLimiting_LoginEndpoint_BlockedAtSixthAttempt()
        {
            // Sensitive auth endpoint: 5 attempts/min, 6th must 429.
            var cache = new MemoryCache(new MemoryCacheOptions());
            var middleware = new RateLimitingMiddleware(
                (ctx) => Task.CompletedTask, cache);

            DefaultHttpContext context = null;
            for (int i = 0; i < 5; i++)
            {
                context = NewContext("127.0.0.1", "/api/Users/LoginAndCreateSession");
                await middleware.InvokeAsync(context);
                Assert.Equal(200, context.Response.StatusCode);
            }

            // 6th attempt: throttled
            context = NewContext("127.0.0.1", "/api/Users/LoginAndCreateSession");
            await middleware.InvokeAsync(context);
            Assert.Equal(429, context.Response.StatusCode);
        }

        [Fact]
        public async Task RateLimiting_RegisterEndpoint_BlockedAtFourthAttempt()
        {
            // Account-creation endpoint: 3 attempts/min, 4th must 429.
            var cache = new MemoryCache(new MemoryCacheOptions());
            var middleware = new RateLimitingMiddleware(
                (ctx) => Task.CompletedTask, cache);

            DefaultHttpContext context = null;
            for (int i = 0; i < 3; i++)
            {
                context = NewContext("127.0.0.1", "/api/Users/RegisterUser");
                await middleware.InvokeAsync(context);
                Assert.Equal(200, context.Response.StatusCode);
            }

            context = NewContext("127.0.0.1", "/api/Users/RegisterUser");
            await middleware.InvokeAsync(context);
            Assert.Equal(429, context.Response.StatusCode);
        }

        [Fact]
        public async Task RateLimiting_BucketsArePerEndpoint()
        {
            // Hitting the login limit must NOT block unrelated endpoints —
            // a legitimate user shouldn't lose access to character browsing
            // because someone (or themselves) fat-fingered the login form.
            var cache = new MemoryCache(new MemoryCacheOptions());
            var middleware = new RateLimitingMiddleware(
                (ctx) => Task.CompletedTask, cache);

            for (int i = 0; i < 6; i++)
            {
                await middleware.InvokeAsync(NewContext("127.0.0.1", "/api/Users/LoginAndCreateSession"));
            }

            // GetAllCharacters falls under the default 60/min — still allowed.
            var ctxOther = NewContext("127.0.0.1", "/api/Users/GetAllCharacters");
            await middleware.InvokeAsync(ctxOther);
            Assert.Equal(200, ctxOther.Response.StatusCode);
        }

        [Fact]
        public async Task RateLimiting_PathMatchingIsCaseInsensitive()
        {
            // The UE5 OWSPlugin sends Unreal-cased URLs (e.g. /api/Users/loginandcreatesession);
            // the limit must apply regardless of casing.
            var cache = new MemoryCache(new MemoryCacheOptions());
            var middleware = new RateLimitingMiddleware(
                (ctx) => Task.CompletedTask, cache);

            for (int i = 0; i < 5; i++)
            {
                await middleware.InvokeAsync(NewContext("127.0.0.1", "/API/USERS/LOGINANDCREATESESSION"));
            }

            var ctx = NewContext("127.0.0.1", "/api/users/loginandcreatesession");
            await middleware.InvokeAsync(ctx);
            Assert.Equal(429, ctx.Response.StatusCode);
        }
    }
}
