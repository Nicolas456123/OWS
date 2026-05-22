using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using OWSShared.Interfaces;
using Serilog;

namespace OWSShared.Middleware
{
    public class StoreCustomerGUIDMiddleware : IMiddleware
    {
        private readonly IHeaderCustomerGUID _customerGuid;

        public StoreCustomerGUIDMiddleware(IHeaderCustomerGUID customerGuid)
        {
            _customerGuid = customerGuid;
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            try
            {
                _customerGuid.CustomerGUID = Guid.Parse(context.Request.Headers.FirstOrDefault(x =>
                    string.Equals(x.Key, "X-CustomerGUID", StringComparison.CurrentCultureIgnoreCase)).Value.ToString());

                if (_customerGuid.CustomerGUID == Guid.Empty)
                {
                    context.Response.Clear();
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Invalid or missing X-CustomerGUID header");
                    return;
                }
            }
            catch (Exception ex)
            {
                // Debug-level: malformed/missing X-CustomerGUID is a normal client error,
                // not a server fault. Bumping to Error would drown legitimate signal in noise.
                Log.Debug(ex, "StoreCustomerGUID rejected header");
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Invalid or missing X-CustomerGUID header");
                return;
            }

            await next(context);
        }
    }
}
