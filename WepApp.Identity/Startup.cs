using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Reflection;
using WepApp.Identity.Helper;

namespace WepApp.Identity
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });


            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);


            services.AddIdentity<MyUser, IdentityRole>(options =>
            {
                options.SignIn.RequireConfirmedEmail = true;
                //complexidade de senha (didático)
                options.Password.RequireDigit = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 4;

                //bloqueio por tentativas erradas
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;
                //options.Lockout.DefaultLockoutTimeSpan

            })
                .AddEntityFrameworkStores<MyUserDbContext>()
                .AddDefaultTokenProviders()                    //provedor de token padrão
                .AddPasswordValidator<NaoContemValidadorSenha<MyUser>>();

            services.ConfigureApplicationCookie(options => options.LoginPath = "/Home/Login");
            services.AddScoped<IUserClaimsPrincipalFactory<MyUser>, MyUserClaimsPrincipalFactory>();
            services.Configure<DataProtectionTokenProviderOptions>(
                options => options.TokenLifespan = TimeSpan.FromHours(3));          //informo que o token gerado vai expirar em 3 horas


            //services.AddScoped<IUserStore<MyUser>,
            //    UserOnlyStore<MyUser, MyUserDbContext>>();
            //services.AddAuthentication("cookies")
            //  .AddCookie("cookies", options => options.LoginPath = "/Home/Login");

            var connectionstring = @"Integrated Security = SSPI; Persist Security Info = False; Initial Catalog = IdentityCurso; Data Source = SEUHOST\SQLEXPRESS";

            var migrationAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            services.AddDbContext<MyUserDbContext>(opt =>
            opt.UseSqlServer(connectionstring, sql => sql.MigrationsAssembly(migrationAssembly)));

          
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseAuthentication();

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
