using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.ViewComponents;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SimpleInjector;
using SimpleInjector.Lifestyles;
using SimpleInjector.Integration.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Swagger;
using Microsoft.AspNetCore.Authentication;
using System.Text.Encodings.Web;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using OWSData.Repositories.Interfaces;
using OWSData.Repositories.Implementations;
using OWSPublicAPI.Requests;
using OWSShared.Interfaces;
using OWSShared.Implementations;
using OWSShared.Middleware;
using OWSShared.Services;
using OWSExternalLoginProviders.Interfaces;
using OWSExternalLoginProviders.Options;
using OWSExternalLoginProviders.Extensions;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.Hosting;
using System.IO;
using Microsoft.AspNetCore.DataProtection;
using Serilog;


namespace OWSPublicAPI
{
    public class Startup
    {
        //Container container;
        private Container container = new SimpleInjector.Container();

        public Startup(IConfiguration configuration)
        {
            container.Options.ResolveUnregisteredConcreteTypes = false;
            //container = new Container();

            Configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .Build();
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo("./temp/DataProtection-Keys"));

            services.AddCors(options =>
            {
                options.AddPolicy("OWSCorsPolicy", builder =>
                {
                    // Explicit allow-list: never AllowAnyHeader/Method on a public API.
                    // - X-CustomerGUID: OWS tenant identifier (StoreCustomerGUIDMiddleware).
                    // - Content-Type/Accept: standard JSON content negotiation.
                    // - Authorization: reserved for future JWT/Bearer rollout.
                    // OPTIONS is required for browser CORS preflight; GET/POST cover every
                    // OWSPublicAPI action (no PUT/DELETE/PATCH endpoints in this service).
                    builder
                        .WithHeaders("X-CustomerGUID", "Content-Type", "Accept", "Authorization")
                        .WithMethods("GET", "POST", "OPTIONS")
                        .SetIsOriginAllowedToAllowWildcardSubdomains()
                        .WithOrigins(
                            Configuration.GetSection("AllowedCorsOrigins").Get<string[]>()
                            ?? new[] { "https://localhost", "http://localhost" }
                        );
                });
            });

            services.AddMemoryCache();
            //services.AddMvc();

            // Redis cache — singleton: ConnectionMultiplexer is thread-safe and expensive to create
            services.AddSingleton<IHWRedisCacheService, HWRedisCacheService>();

            services.AddHttpContextAccessor();

            services.AddMvcCore(config => {
                config.EnableEndpointRouting = false;
                //IHttpRequestStreamReaderFactory readerFactory = services.BuildServiceProvider().GetRequiredService<IHttpRequestStreamReaderFactory>();
                //config.ModelBinderProviders.Insert(0, new Microsoft.AspNetCore.Mvc.ModelBinding.Binders.BodyModelBinderProvider(config.InputFormatters, readerFactory));
                //config.ModelBinderProviders.Insert(0, new QueryModelBinderProvider(container));
            })
            .AddViews()
            .AddApiExplorer()
            // Force PascalCase JSON output: the UE5 OWSPlugin C++ deserializer is case-sensitive
            // and expects field names matching the C# DTO PascalCase (UserSessionGUID, CharName, X, Y, Z, ZoneName...).
            // Inbound requests from the plugin use Unreal's auto-camelCase (e.g. userSessionGUId) so we accept case-insensitive input.
            .AddJsonOptions(options => {
                options.JsonSerializerOptions.PropertyNamingPolicy = null;
                options.JsonSerializerOptions.DictionaryKeyPolicy = null;
                options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
            })
            .SetCompatibilityVersion(CompatibilityVersion.Version_3_0);

            services.AddSimpleInjector(container, options => {
                options.AddAspNetCore()
                    .AddControllerActivation()
                    .AddViewComponentActivation();
                    //.AddPageModelActivation()
                    //.AddTagHelperActivation();
            });

            services.AddSwaggerGen(c => {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Open World Server Authentication API", Version = "v1" });

                c.AddSecurityDefinition("X-CustomerGUID", new OpenApiSecurityScheme
                {
                    Description = "Authorization header using the X-CustomerGUID scheme",
                    Name = "X-CustomerGUID",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "X-CustomerGUID"
                });

                c.OperationFilter<SwaggerSecurityRequirementsDocumentFilter>();

                var filePath = Path.Combine(System.AppContext.BaseDirectory, "OWSPublicAPI.xml");
                c.IncludeXmlComments(filePath);
            });

            var apiPathOptions = new OWSShared.Options.APIPathOptions();
            Configuration.GetSection(OWSShared.Options.APIPathOptions.SectionName).Bind(apiPathOptions);

            services.AddHttpClient("OWSInstanceManagement", c =>
            {
                c.BaseAddress = new Uri(apiPathOptions.InternalInstanceManagementApiURL);
                c.DefaultRequestHeaders.Add("Accept", "application/json");
                c.DefaultRequestHeaders.Add("User-Agent", "OWSPublicAPI");
            });

            services.Configure<OWSShared.Options.PublicAPIOptions>(Configuration.GetSection(OWSShared.Options.PublicAPIOptions.SectionName));
            services.Configure<OWSShared.Options.APIPathOptions>(Configuration.GetSection(OWSShared.Options.APIPathOptions.SectionName));
            services.Configure<OWSShared.Options.StorageOptions>(Configuration.GetSection(OWSShared.Options.StorageOptions.SectionName));

            // Register And Validate External Login Provider Options
            // services.ConfigureAndValidate<EpicOnlineServicesOptions>(ExternalLoginProviderOptions.EpicOnlineServices, Configuration.GetSection($"{ExternalLoginProviderOptions.SectionName}:{ExternalLoginProviderOptions.EpicOnlineServices}"));

            InitializeContainer(services);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseSimpleInjector(container);

            app.UseMiddleware<RateLimitingMiddleware>();
            app.UseMiddleware<StoreCustomerGUIDMiddleware>(container);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseSerilogRequestLogging(options =>
            {
                options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
                {
                    diagnosticContext.Set("RequestHost", httpContext.Request.Host.Value);
                    diagnosticContext.Set("UserAgent", httpContext.Request.Headers["User-Agent"].ToString());
                };
            });

            //app.UseHttpsRedirection();

            //app.UseAuthentication();

            //app.UseStaticFiles();
            app.UseRouting();
            app.UseCors("OWSCorsPolicy");

            app.UseMvc();

            app.UseSwagger(/*c =>
            {
                c.RouteTemplate =
                    "api-docs/{documentName}/swagger.json";
            }*/);
            app.UseSwaggerUI(c => 
            {
                //c.RoutePrefix = "api-docs";
                c.SwaggerEndpoint("./v1/swagger.json", "Open World Server Authentication API");
            });

            container.Verify();
        }

        private void InitializeContainer(IServiceCollection services)
        {
            var OWSStorageConfig = Configuration.GetSection("OWSStorageConfig");
            if (OWSStorageConfig.Exists())
            {
                string dbBackend = OWSStorageConfig.GetValue<string>("OWSDBBackend");

                switch (dbBackend)
                {
                    case "postgres":
                        container.Register<ICharactersRepository, OWSData.Repositories.Implementations.Postgres.CharactersRepository>(Lifestyle.Transient);
                        container.Register<IUsersRepository, OWSData.Repositories.Implementations.Postgres.UsersRepository>(Lifestyle.Transient);
                        break;
                    case "mysql":
                        container.Register<ICharactersRepository, OWSData.Repositories.Implementations.MySQL.CharactersRepository>(Lifestyle.Transient);
                        container.Register<IUsersRepository, OWSData.Repositories.Implementations.MySQL.UsersRepository>(Lifestyle.Transient);
                        break;
                    default: // Default to MSSQL
                        container.Register<ICharactersRepository, OWSData.Repositories.Implementations.MSSQL.CharactersRepository>(Lifestyle.Transient);
                        container.Register<IUsersRepository, OWSData.Repositories.Implementations.MSSQL.UsersRepository>(Lifestyle.Transient);
                        break;
                }
            }

            container.Register<IPublicAPIInputValidation, DefaultPublicAPIInputValidation>(Lifestyle.Singleton);
            container.Register<ICustomCharacterDataSelector, DefaultCustomCharacterDataSelector>(Lifestyle.Singleton);
            container.Register<IGetReadOnlyPublicCharacterData, DefaultGetReadOnlyPublicCharacterData>(Lifestyle.Singleton);
            container.Register<IHeaderCustomerGUID, HeaderCustomerGUID>(Lifestyle.Scoped);

            // HMAC verification in StoreCustomerGUIDMiddleware needs IConfiguration to read
            // the OWSHmac section. SimpleInjector doesn't auto-cross-wire framework services
            // and Container.Options.ResolveUnregisteredConcreteTypes is false, so without
            // these two lines the SimpleInjectorMiddlewareFactory throws ActivationException
            // at first request (and container.Verify() throws at startup). Keep Scoped: the
            // middleware reads IHeaderCustomerGUID which is per-request.
            container.RegisterInstance<IConfiguration>(Configuration);
            container.Register<StoreCustomerGUIDMiddleware>(Lifestyle.Scoped);

            var externalloginproviderfactory = new ExternalLoginProviderFactory(container);

            // Register External Login Provider
            // externalloginproviderfactory.Register<OWSExternalLoginProviders.Implementations.EpicOnlineServicesLoginProvider>(ExternalLoginProviderOptions.EpicOnlineServices);

            container.RegisterInstance<IExternalLoginProviderFactory>(externalloginproviderfactory);

            var provider = services.BuildServiceProvider();
            container.RegisterInstance<IServiceProvider>(provider);
            
            /*
            //Doesn't do anything
            var requestAssembly = typeof(IRequest).GetTypeInfo().Assembly;
            container.Collection.Register(typeof(IRequest), new[] { requestAssembly });
            */

            //Doesn't work
            //container.Register(typeof(IRequestHandler<,>), new[] { typeof(IRequestHandler<,>).Assembly });

            //Doesn't work
            //var requestHandlerAssembly = typeof(IRequestHandler<,>).GetTypeInfo().Assembly;
            //container.Collection.Register(typeof(IRequestHandler<,>), new[] { requestHandlerAssembly });

            /*
            //These work, but are too slow
            container.Register<Requests.Characters.GetByNameRequest>();
            container.Register<Requests.Users.LoginAndCreateSessionRequest>();
            container.Register<Requests.Users.GetUserSessionRequest>();
            container.Register<Requests.Users.GetServerToConnectToRequest>();
            container.Register<Requests.Users.UserSessionSetSelectedCharacterRequest>();
            */
        }
    }
}
