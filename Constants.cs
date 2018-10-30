namespace ePin
{
    public class MyCompanyConstants
    {
        // https://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html
        public const string MultiFactor = "http://schemas.openid.net/pape/policies/2007/06/multi-factor";

        public const string MyCompanyAuthenticationScheme = "MyCompanyScheme";
        public const string MyCompanyAuthenticationCookie = "MyCompanyCookie";
        public const string ePinMfaFirstAuthenticationScheme = "mfaFirstScheme";
        public const string ePinMfaFirstAuthenticationCookie = "mfaFirstCookie";
        public const string ePinMfaSecondAuthenticationScheme = "mfaSecondScheme";
        public const string ePinMfaSecondAuthenticationCookie = "mfaSecondCookie";
    }
}