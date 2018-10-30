using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using ePin;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace MyCompany
{
    public class Startup
    {
        private IConfiguration Configuration { get; set; }

        //Start of Program
        public static void Main(string[] args)
        {
            var host = new WebHostBuilder()
                 .UseContentRoot(Directory.GetCurrentDirectory())
                 .UseIISIntegration()
                 .UseKestrel()
                 .UseStartup<Startup>()
                 .Build();

            host.Run();
        }

        public Startup(IConfiguration config, IHostingEnvironment env)
        {
            if (env.IsEnvironment(""))
            {
                env.EnvironmentName = "Production";
            }
            var builderConfiguration = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);

            Configuration = builderConfiguration.Build();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseMvc();
        }

        private Task RemoteAuthFail(RemoteFailureContext context)
        {
            context.Response.Redirect("/");
            context.HandleResponse();
            return Task.CompletedTask;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = ePin.MyCompanyConstants.MyCompanyAuthenticationScheme;
            })
            .AddCookie(MyCompanyConstants.ePinMfaFirstAuthenticationCookie, options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromHours(1);
            })
            .AddCookie(MyCompanyConstants.ePinMfaSecondAuthenticationCookie, options =>
              {
                  options.ExpireTimeSpan = TimeSpan.FromHours(1);
              })
            .AddCookie(ePin.MyCompanyConstants.MyCompanyAuthenticationScheme, options =>
                 {
                     options.ExpireTimeSpan = TimeSpan.FromHours(1);
                     options.Cookie.Name = ePin.MyCompanyConstants.MyCompanyAuthenticationCookie;
                 })
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
              {
                  options.RequireHttpsMetadata = true;
                  options.GetClaimsFromUserInfoEndpoint = true;
                  options.SaveTokens = true;

                  // Note: setting the Authority allows the OIDC client middleware to automatically
                  // retrieve the identity provider's configuration and spare you from setting
                  // the different endpoints URIs or the token validation parameters explicitly.
                  options.Authority = Configuration.GetSection("App").GetSection("ePinAuthorityUrl").Value; // ;
                  options.ClientId = Configuration.GetSection("App").GetSection("ClientID").Value;
                  options.ClientSecret = Configuration.GetSection("App").GetSection("ClientSecret").Value;

                  // Use the authorization code flow.
                  options.ResponseType = OpenIdConnectResponseType.IdToken;
                  options.CallbackPath = new PathString("/signin-oidc/");
                  options.SignInScheme = ePin.MyCompanyConstants.MyCompanyAuthenticationScheme;

                  options.Scope.Clear();
                  options.Scope.Add("openid");
                  options.Scope.Add("email");
                  //Force login - ignore cookie
                  //options.Prompt = Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectPrompt.Login;

                  options.SecurityTokenValidator = new JwtSecurityTokenHandler
                  {
                      // Disable the built-in JWT claims mapping feature.
                      InboundClaimTypeMap = new Dictionary<string, string>()
                  };

                  options.TokenValidationParameters.NameClaimType = "name";
                  options.Events.OnRemoteFailure = RemoteAuthFail;
              })

            //For Multiple Factors
            .AddOpenIdConnect(MyCompanyConstants.ePinMfaFirstAuthenticationScheme, options =>
           {
               options.RequireHttpsMetadata = true;
               options.GetClaimsFromUserInfoEndpoint = true;
               options.SaveTokens = true;

               options.Authority = Configuration.GetSection("AppMfaFirst").GetSection("ePinAuthorityUrl").Value; // ;
               options.ClientId = Configuration.GetSection("AppMfaFirst").GetSection("ClientID").Value;
               options.ClientSecret = Configuration.GetSection("AppMfaFirst").GetSection("ClientSecret").Value;

               options.ResponseType = OpenIdConnectResponseType.IdToken;
               options.CallbackPath = new PathString("/signin-oidc-mfa-first/");
               options.SignInScheme = MyCompanyConstants.ePinMfaFirstAuthenticationCookie;

               options.Scope.Clear();
               options.Scope.Add("openid");
               options.Scope.Add("email");
               //Force login - ignore cookie
               options.Prompt = Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectPrompt.Login;

               options.Events = new OpenIdConnectEvents
               {
                   OnRedirectToIdentityProvider = context =>
                   {
                       if (context.Properties.Items.ContainsKey(OpenIdConnectParameterNames.AcrValues))
                       {
                           var acr_values = context.Properties.Items[OpenIdConnectParameterNames.AcrValues];
                           if (!string.IsNullOrEmpty(acr_values))
                           {
                               context.ProtocolMessage.SetParameter(OpenIdConnectParameterNames.AcrValues, acr_values);
                           }
                       }

                       return Task.FromResult(0);
                   }
               };
               options.SecurityTokenValidator = new JwtSecurityTokenHandler
               {
                   // Disable the built-in JWT claims mapping feature.
                   InboundClaimTypeMap = new Dictionary<string, string>()
               };

               options.TokenValidationParameters.NameClaimType = "name";
               options.Events.OnRemoteFailure = RemoteAuthFail;
           })
            .AddOpenIdConnect(MyCompanyConstants.ePinMfaSecondAuthenticationScheme, options =>
          {
              options.RequireHttpsMetadata = true;
              options.GetClaimsFromUserInfoEndpoint = true;
              options.SaveTokens = true;

              options.Authority = Configuration.GetSection("AppMfaSecond").GetSection("ePinAuthorityUrl").Value; // ;
              options.ClientId = Configuration.GetSection("AppMfaSecond").GetSection("ClientID").Value;
              options.ClientSecret = Configuration.GetSection("AppMfaSecond").GetSection("ClientSecret").Value;

              options.ResponseType = OpenIdConnectResponseType.IdToken;
              options.CallbackPath = new PathString("/signin-oidc-mfa-second/");
              options.SignInScheme = MyCompanyConstants.ePinMfaSecondAuthenticationCookie;
              options.Scope.Clear();
              options.Scope.Add("openid");
              options.Scope.Add("email");
              //Force login - ignore cookie
              options.Prompt = Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectPrompt.Login;

              options.Events = new OpenIdConnectEvents
              {
                  OnRedirectToIdentityProvider = context =>
                  {
                      if (context.Properties.Items.ContainsKey(OpenIdConnectParameterNames.LoginHint))
                      {
                          var login_hint = context.Properties.Items[OpenIdConnectParameterNames.LoginHint];
                          if (!string.IsNullOrEmpty(login_hint))
                          {
                              context.ProtocolMessage.SetParameter(OpenIdConnectParameterNames.LoginHint, login_hint);
                          }
                      }

                      if (context.Properties.Items.ContainsKey(OpenIdConnectParameterNames.AcrValues))
                      {
                          var acr_values = context.Properties.Items[OpenIdConnectParameterNames.AcrValues];
                          if (!string.IsNullOrEmpty(acr_values))
                          {
                              context.ProtocolMessage.SetParameter(OpenIdConnectParameterNames.AcrValues, acr_values);
                          }
                      }

                      return Task.FromResult(0);
                  }
              };

              options.Events.OnRemoteFailure = RemoteAuthFail;
              options.SecurityTokenValidator = new JwtSecurityTokenHandler
              {
                  InboundClaimTypeMap = new Dictionary<string, string>()
              };

              options.TokenValidationParameters.NameClaimType = "name";
              options.Events.OnRemoteFailure = RemoteAuthFail;
          });
            services.AddMvc();
        }
    }
}