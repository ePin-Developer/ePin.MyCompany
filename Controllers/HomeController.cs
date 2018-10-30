using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MyCompany.Models;
using System.Collections.Generic;
using System.Security.Claims;

namespace ClientApp.Controllers
{
    public class HomeController : Controller
    {
        #region OneFactor

        [HttpGet("~/HomeOneFactor")]
        public ActionResult HomeOneFactor()
        {
            return View("HomeOneFactor");
        }

        #endregion OneFactor

        #region MfaFirst

        [HttpGet("~/HomeMfaFirst")]
        public ActionResult HomeMfaFirst(MyCompanyModel model)
        {
            return RedirectToAction("signinMfaFirst", "Authentication");
        }

        #endregion MfaFirst

        #region MfaSecond

        [HttpGet("~/HomeMfaSecond")]
        public ActionResult HomeMfaSecond(MyCompanyModel model)
        {
            ModelState.Clear();
            return View("HomeMfaSecond", model);
        }

        #endregion MfaSecond

        #region Actions

        [HttpGet("~/")]
        public ActionResult Index()
        {
            return View("Home");
        }

        [Authorize(AuthenticationSchemes = ePin.MyCompanyConstants.MyCompanyAuthenticationScheme)]
        [HttpGet("~/Authenticated")]
        public ActionResult Authenticated()
        {
            var model = new MyCompanyModel();
            if (User?.Identity?.IsAuthenticated ?? false)
            {
                var identity = (ClaimsIdentity)User.Identity;
                IEnumerable<Claim> claims = identity.Claims;

                var email = ((ClaimsIdentity)User.Identity).FindFirst(ClaimTypes.Email)?.Value;
                if (!string.IsNullOrWhiteSpace(email))
                {
                    model.EmailAddress = email;
                }
            }
            return View("Authenticated", model);
        }

        #endregion Actions
    }
}