using System.ComponentModel.DataAnnotations;

namespace WepApp.Identity.Models
{
    public class TwoFactorModel
    {
        [Required]
        public string Token { get; set; }
    }
}
