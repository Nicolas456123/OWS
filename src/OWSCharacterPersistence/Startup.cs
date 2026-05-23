using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using OWSData.Repositories.Interfaces;
using OWSShared.Implementations;
using OWSShared.Interfaces;
using OWSShared.Middleware;
using SimpleInjector;

namespace OWSCharacterPersistence
{
    public class Startup
    {
        //Container container;
        private Container container = new SimpleInjector.Container();

        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            container.Options.ResolveUnregisteredConcreteTypes = false;

            Configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .Build();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo("./temp/DataProtection-Keys"));

            // Required by RateLimitingMiddleware (per-IP, per-endpoint quota cache).
            services.AddMemoryCache();

            services.AddHttpContextAccessor();

            services.AddMvcCore(config =>
            {
                config.EnableEndpointRouting = false;
                //IHttpRequestStreamReaderFactory readerFactory = services.BuildServiceProvider().GetRequiredService<IHttpRequestStreamReaderFactory>();
                //config.ModelBinderProviders.Insert(0, new Microsoft.AspNetCore.Mvc.ModelBinding.Binders.BodyModelBinderProvider(config.InputFormatters, readerFactory));
                //config.ModelBinderProviders.Insert(0, new QueryModelBinderProvider(container));
            })
            .AddViews()
            .AddApiExplorer();

            services.AddSimpleInjector(container, options => {
                options.AddAspNetCore()
                    .AddControllerActivation()
                    .AddViewComponentActivation();
                //.AddPageModelActivation()
                //.AddTagHelperActivation();
            });

            services.AddSwaggerGen(c => {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Open World Server Character Persistence API", Version = "v1" });

                c.AddSecurityDefinition("X-CustomerGUID", new OpenApiSecurityScheme
                {
                    Description = "Authorization header using the X-CustomerGUID scheme",
                    Name = "X-CustomerGUID",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "X-CustomerGUID"
                });

                c.OperationFilter<SwaggerSecurityRequirementsDocumentFilter>();

                var filePath = Path.Combine(System.AppContext.BaseDirectory, "OWSCharacterPersistence.xml");
                c.IncludeXmlComments(filePath);
            });

            services.Configure<OWSShared.Options.StorageOptions>(Configuration.GetSection(OWSShared.Options.StorageOptions.SectionName));
            services.Configure<OWSShared.Options.APIPathOptions>(Configuration.GetSection(OWSShared.Options.APIPathOptions.SectionName));
            services.Configure<OWSShared.Options.RabbitMQOptions>(Configuration.GetSection(OWSShared.Options.RabbitMQOptions.SectionName));

            InitializeContainer(services);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseSimpleInjector(container);

            // Apply the same RateLimitingMiddleware that protects OWSPublicAPI:
            // default 60 req/min/IP, plus tighter quotas on sensitive endpoints
            // (defined in RateLimitingMiddleware.EndpointLimits). Bound to the
            // pipeline before the CustomerGUID check so brute-force attempts get
            // throttled even when they carry a guessed-but-invalid header.
            app.UseMiddleware<RateLimitingMiddleware>();

            app.UseMiddleware<StoreCustomerGUIDMiddleware>(container);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            //app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            //app.UseAuthorization();

            app.UseMvc();

            app.UseSwagger(/*c =>
            {
                c.RouteTemplate =
                    "api-docs/{documentName}/swagger.json";
            }*/);
            app.UseSwaggerUI(c =>
            {
                //c.RoutePrefix = "api-docs";
                c.SwaggerEndpoint("./v1/swagger.json", "Open World Server Character Persistence API");
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
                        container.Register<ICharactersRepository, OWSData.Repositories.Implementations.Postgres.CharactersRepository>(Lifestyle.Scoped);
                        container.Register<IUsersRepository, OWSData.Repositories.Implementations.Postgres.UsersRepository>(Lifestyle.Scoped);
                        break;
                    case "mysql":
                        container.Register<ICharactersRepository, OWSData.Repositories.Implementations.MySQL.CharactersRepository>(Lifestyle.Scoped);
                        container.Register<IUsersRepository, OWSData.Repositories.Implementations.MySQL.UsersRepository>(Lifestyle.Scoped);
                        break;
                    default: // Default to MSSQL
                        container.Register<ICharactersRepository, OWSData.Repositories.Implementations.MSSQL.CharactersRepository>(Lifestyle.Scoped);
                        container.Register<IUsersRepository, OWSData.Repositories.Implementations.MSSQL.UsersRepository>(Lifestyle.Scoped);
                        break;
                }
            }
            container.Register<IHeaderCustomerGUID, HeaderCustomerGUID>(Lifestyle.Scoped);

            // HMAC verification in StoreCustomerGUIDMiddleware needs IConfiguration to read
            // the OWSHmac section. SimpleInjector doesn't auto-cross-wire framework services
            // and Container.Options.ResolveUnregisteredConcreteTypes is false, so without
            // these two lines the SimpleInjectorMiddlewareFactory throws ActivationException
            // at first request (and container.Verify() throws at startup). Keep Scoped: the
            // middleware reads IHeaderCustomerGUID which is per-request.
            container.RegisterInstance<IConfiguration>(Configuration);
            container.Register<StoreCustomerGUIDMiddleware>(Lifestyle.Scoped);

            var provider = services.BuildServiceProvider();
            container.RegisterInstance<IServiceProvider>(provider);
        }
    }
}
