using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.ComponentModel.DataAnnotations;

namespace MyCompany.Models
{
    public class MyCompanyModel
    {
        [StringLength(255, ErrorMessage = "Max 255 characters")]
        [Required(ErrorMessage = "This field email address is required.")]
        [RegularExpression("^[a-z0-9_\\+-]+(\\.[a-z0-9_\\+-]+)*@[a-z0-9-]+(\\.[a-z0-9]+)*\\.([a-z]{2,4})$", ErrorMessage = "Invalid email format.")]
        public string EmailAddress { get; set; }

        [StringLength(50, ErrorMessage = "Max 50 characters")]
        [Required(ErrorMessage = "This field password is required.")]
        public string Password { get; set; }

        [BindNever]
        public bool IsAuthenticated { get; set; } = false;
    }
}