using System.ComponentModel.DataAnnotations;

namespace WepApp.Identity.Models
{
    public class ForgotPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

    }
}
