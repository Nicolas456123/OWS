using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace OWSShared.Middleware
{
    public class RateLimitingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IMemoryCache _cache;

        // Default quota for any endpoint not explicitly listed below.
        public const int DefaultMaxRequestsPerMinute = 60;

        // Per-endpoint quotas. Keys MUST be lowercase, comparison is case-insensitive
        // anyway via the IEqualityComparer, but path lookup is also lowercased for
        // consistency with cache key derivation. Sensitive endpoints (auth, account
        // creation) get stricter quotas to slow brute-force / enumeration attacks.
        private static readonly IReadOnlyDictionary<string, int> EndpointLimits =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["/api/users/loginandcreatesession"] = 5,
                ["/api/users/registeruser"] = 3,
            };

        public RateLimitingMiddleware(RequestDelegate next, IMemoryCache cache)
        {
            _next = next;
            _cache = cache;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var pathKey = context.Request.Path.HasValue
                ? context.Request.Path.Value.ToLowerInvariant()
                : "/";
            var limit = EndpointLimits.TryGetValue(pathKey, out var endpointLimit)
                ? endpointLimit
                : DefaultMaxRequestsPerMinute;
            var cacheKey = $"RateLimit_{ipAddress}_{pathKey}";

            var requestCount = _cache.GetOrCreate(cacheKey, entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1);
                return 0;
            });

            if (requestCount >= limit)
            {
                context.Response.StatusCode = (int)HttpStatusCode.TooManyRequests;
                context.Response.Headers["Retry-After"] = "60";
                await context.Response.WriteAsync("Rate limit exceeded. Please try again later.");
                return;
            }

            _cache.Set(cacheKey, requestCount + 1, TimeSpan.FromMinutes(1));
            await _next(context);
        }
    }
}
