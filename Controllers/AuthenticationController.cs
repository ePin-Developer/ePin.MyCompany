using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using ePin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Linq;
using MyCompany.Models;
using static Microsoft.IdentityModel.Tokens.Saml.SamlConstants;

namespace ClientApp.Controllers
{
    public class AuthenticationController : Controller
    {
        #region OneFactor

        [HttpGet("~/signin")]
        public ActionResult SignIn()
        {
            var props = new AuthenticationProperties()
            {
                RedirectUri = "/signin-oidc",
                Items =
                {
                    { "scheme", OpenIdConnectDefaults.AuthenticationScheme },
                }
            };
            return Challenge(props, OpenIdConnectDefaults.AuthenticationScheme);
        }

        [HttpPost("~/signinOneFactor")]
        public async Task<IActionResult> SigninOneFactor(MyCompanyModel model)
        {
            ViewData["message"] = "";
            if (ModelState.IsValid)
            {
                // WRITE YOUR CODE TO AUTHENTICATE email/password
                if (model.EmailAddress == "demo@epin.me" && model.Password == "1234")
                {
                    // create claims
                    model.IsAuthenticated = true;
                    await SignInAsync(model);
                    return Redirect("/Authenticated");
                }
                else
                {
                    ViewData["message"] = "Invalid login!";
                    return View("HomeOneFactor", model);
                }
            }
            return View("HomeOneFactor", model);
        }

        [Authorize(AuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme)]
        [HttpGet("~/signin-oidc/")]
        public async Task<IActionResult> Signin_oidc()
        {
            if (User?.Identity?.IsAuthenticated ?? false)
            {
                var identity = (ClaimsIdentity)User.Identity;
                IEnumerable<Claim> claims = identity.Claims;

                var name = ((ClaimsIdentity)User.Identity).FindFirst("name")?.Value;
                if (!string.IsNullOrWhiteSpace(name))
                {
                    var result = await HttpContext.AuthenticateAsync(OpenIdConnectDefaults.AuthenticationScheme);
                    var model = new MyCompanyModel()
                    {
                        EmailAddress = name,
                        IsAuthenticated = true
                    };

                    // after signout this will redirect to your provided target
                    await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
                    await SignInAsync(model, result.Principal.Identities);
                    return Redirect("/Authenticated");
                }
                else
                {
                    throw new Exception("External authentication error");
                }
            }
            return View("Authenticated");
        }

        #endregion OneFactor

        #region MfaFirst

        [HttpGet("~/signinMfaFirst")]
        public ActionResult SignInMfaFirst()
        {
            var props = new AuthenticationProperties()
            {
                RedirectUri = "/signin-oidc-mfa-first",
                Items =
                {
                    { "scheme", ePin.MyCompanyConstants.ePinMfaFirstAuthenticationScheme },
                    { OpenIdConnectParameterNames.AcrValues, ePin.MyCompanyConstants.MultiFactor}
                }
            };
            return Challenge(props, MyCompanyConstants.ePinMfaFirstAuthenticationScheme);
        }

        [Authorize(AuthenticationSchemes = ePin.MyCompanyConstants.MyCompanyAuthenticationScheme)]
        [HttpGet("~/signinAfterMfaFirst")]
        public IActionResult SigninAfterMfaFirst()
        {
            var model = new MyCompanyModel();

            if (User?.Identity?.IsAuthenticated ?? false)
            {
                var email = ((ClaimsIdentity)User.Identity).FindFirst(ClaimTypes.Email)?.Value;
                model.EmailAddress = email;
            }

            return View("HomeMfaFirst", model);
        }

        [Authorize]
        [HttpPost("~/signinAfterMfaFirst")]
        public async Task<IActionResult> SigninAfterMfaFirstAsync(MyCompanyModel model)
        {
            ViewData["message"] = "";
            if (ModelState.IsValid)
            {
                // WRITE YOUR CODE TO AUTHENTICATE email/password
                if (model.Password == "1234")
                {
                    var Identity = (ClaimsIdentity)User.Identity;
                    Identity.RemoveClaim(Identity.FindFirst("IsLocalAuthenticated"));
                    Identity.AddClaim(new Claim("IsLocalAuthenticated", "True"));
                    await SignInAsync(null, User.Identities);
                    return Redirect("/Authenticated");
                }
                else
                {
                    ViewData["message"] = "Invalid login!";
                    return View("HomeMfaFirst", model);
                }
            }
            return View("HomeMfaFirst", model);
        }

        [Authorize(AuthenticationSchemes = ePin.MyCompanyConstants.ePinMfaFirstAuthenticationScheme)]
        [HttpGet("~/signin-oidc-mfa-first/")]
        public async Task<IActionResult> Signin_oidc_mfa_first()
        {
            var mfa = await HttpContext.AuthenticateAsync(ePin.MyCompanyConstants.ePinMfaFirstAuthenticationScheme);
            var externalEmail = GetExternalEmailMfa(mfa);
            if (User?.Identity?.IsAuthenticated ?? false)
            {
                if (!string.IsNullOrWhiteSpace(externalEmail))
                {
                    var result = await HttpContext.AuthenticateAsync(ePin.MyCompanyConstants.ePinMfaFirstAuthenticationScheme);
                    var model = new MyCompanyModel()
                    {
                        EmailAddress = externalEmail,
                        IsAuthenticated = false
                    };

                    await SignInAsync(model, result.Principal.Identities);
                    return Redirect("SigninAfterMfaFirst");
                }
                else
                {
                    throw new Exception("External authentication error");
                }
            }
            return Redirect("/");
        }

        #endregion MfaFirst

        #region MfaSecond

        [AllowAnonymous]
        [HttpPost("~/signinBeforeMfaSecond")]
        public async Task<IActionResult> SigninBeforeMfaSecond(MyCompanyModel model)
        {
            ViewData["message"] = "";
            if (ModelState.IsValid)
            {
                // WRITE YOUR CODE TO AUTHENTICATE email/password
                if (model.Password == "1234")
                {
                    ViewData["message"] = "Email/Password is authenticated.";

                    model.IsAuthenticated = true;
                    await SignInAsync(model);
                    return RedirectToAction("signinMfaSecond", "Authentication");
                }
                else
                {
                    ViewData["message"] = "Invalid login!";
                    return View("HomeMfaSecond", model);
                }
            }
            return View("HomeMfaSecond", model);
        }

        [Authorize(AuthenticationSchemes = ePin.MyCompanyConstants.MyCompanyAuthenticationScheme)]
        [HttpGet("~/signinMfaSecond")]
        public ActionResult SignInMfaSecond()
        {
            var identity = (ClaimsIdentity)User.Identity;
            var email = ((ClaimsIdentity)User.Identity).FindFirst(ClaimTypes.Email)?.Value;

            var props = new AuthenticationProperties()
            {
                RedirectUri = "/signin-oidc-mfa-second",
                Items =
                {
                    { "scheme", ePin.MyCompanyConstants.ePinMfaSecondAuthenticationScheme },
                    { OpenIdConnectParameterNames.LoginHint, email },
                    { OpenIdConnectParameterNames.AcrValues, ePin.MyCompanyConstants.MultiFactor}
                }
            };
            return Challenge(props, MyCompanyConstants.ePinMfaSecondAuthenticationScheme);
        }

        [Authorize(AuthenticationSchemes = ePin.MyCompanyConstants.ePinMfaSecondAuthenticationScheme)]
        [Authorize(AuthenticationSchemes = ePin.MyCompanyConstants.MyCompanyAuthenticationScheme)]
        [HttpGet("~/signin-oidc-mfa-second/")]
        public async Task<IActionResult> Signin_oidc_mfa_second()
        {
            // read external identity from the temporary cookie
            var mfa = await HttpContext.AuthenticateAsync(ePin.MyCompanyConstants.ePinMfaSecondAuthenticationScheme);
            var externalEmail = GetExternalEmailMfa(mfa);

            if (User?.Identity?.IsAuthenticated ?? false)
            {
                // delete temporary cookie used during external authentication
                var identity = (ClaimsIdentity)User.Identity;
                IEnumerable<Claim> claims = identity.Claims;
                var internalEmail = ((ClaimsIdentity)User.Identity).FindFirst(ClaimTypes.Email)?.Value;
                var internalIsLocalAuthenticated = ((ClaimsIdentity)User.Identity).FindFirst("IsLocalAuthenticated")?.Value;
                var internalAuthenticationMethod = ((ClaimsIdentity)User.Identity).FindFirst(ClaimTypes.AuthenticationMethod)?.Value;

                if (string.Equals(externalEmail, internalEmail, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(internalAuthenticationMethod, AuthenticationMethods.PasswordString, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(internalIsLocalAuthenticated, "true", StringComparison.OrdinalIgnoreCase))
                {
                    var model = new MyCompanyModel()
                    {
                        EmailAddress = internalEmail,
                        IsAuthenticated = true
                    };

                    await HttpContext.SignOutAsync(ePin.MyCompanyConstants.ePinMfaSecondAuthenticationScheme);
                    await HttpContext.SignOutAsync(ePin.MyCompanyConstants.ePinMfaSecondAuthenticationCookie);
                    await SignInAsync(model, mfa.Principal.Identities);
                    return Redirect("/Authenticated");
                }
                else
                {
                    throw new Exception("External/Internal authentication error");
                }
            }
            return View("HomeMfaSecond");
        }

        #endregion MfaSecond

        #region Actions

        [HttpGet("~/signup")]
        public ActionResult SignUp()
        {
            return Redirect("https://www.epin.me");
        }

        [HttpGet("~/signout")]
        public async Task<IActionResult> SignOut()
        {
            await HttpContext.SignOutAsync(MyCompanyConstants.MyCompanyAuthenticationScheme);
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
            return View("Home");
        }

        #endregion Actions

        #region Helpers

        private string GetExternalEmailMfa(AuthenticateResult mfaResult)
        {
            var tempUser = mfaResult?.Principal;
            if (tempUser == null)
            {
                throw new Exception("External authentication error");
            }

            // retrieve claims of the external user
            var externalClaims = tempUser.Claims.ToList();

            var externalEmail = externalClaims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
            if (externalEmail == null)
            {
                externalEmail = externalClaims.FirstOrDefault(x => x.Type == "email")?.Value;
            }
            if (externalEmail == null)
            {
                throw new Exception("External authentication unknown email");
            }

            // retrieve claim for amr - should be mfa
            var externalAmrValue = externalClaims.FirstOrDefault(x => x.Type == "amr")?.Value;

            if (string.Equals(externalAmrValue, "mfa", StringComparison.OrdinalIgnoreCase))
            {
                return externalEmail;
            }
            return "";
        }

        private async Task SignInAsync(MyCompanyModel model, IEnumerable<ClaimsIdentity> externalIdentities = null)
        {
            // create principal
            ClaimsPrincipal principal = new ClaimsPrincipal();

            if (model != null)
            {
                List<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.PasswordString),
                    new Claim(ClaimTypes.Email, model.EmailAddress),
                    new Claim("IsLocalAuthenticated", model.IsAuthenticated.ToString()),
                };
                // create identity
                ClaimsIdentity identity = new ClaimsIdentity(claims, ePin.MyCompanyConstants.MyCompanyAuthenticationScheme)
                {
                    Label = ePin.MyCompanyConstants.MyCompanyAuthenticationScheme
                };

                principal.AddIdentity(identity);
            }

            if (externalIdentities != null)
            {
                principal.AddIdentities(externalIdentities);
            }

            // sign in
            await HttpContext.SignInAsync(
                   scheme: ePin.MyCompanyConstants.MyCompanyAuthenticationScheme,
                   principal: principal,
                   properties: new AuthenticationProperties
                   {
                       IsPersistent = true, // for 'remember me' feature
                       ExpiresUtc = DateTime.UtcNow.AddMinutes(20)
                   });
        }

        #endregion Helpers
    }
}