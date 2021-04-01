using System.ComponentModel.DataAnnotations;

namespace DTO
{
    public class SendEmailDTO
    {
        public string Subject { get; set; }
        [Required]
        public string Message { get; set; }
    }
}