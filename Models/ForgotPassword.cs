using System.ComponentModel.DataAnnotations;

namespace Models
{
    public class ForgotPassword
    {
        [Required]
        public string Username { get; set; }
    }
}