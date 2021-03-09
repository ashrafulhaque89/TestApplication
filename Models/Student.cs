using System.ComponentModel.DataAnnotations;

namespace Models
{
    public class Students
    {
        [Key]
        public int Id { get; set; }
        public string grade { get; set; }

    }
}