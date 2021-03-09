using System.ComponentModel.DataAnnotations;

namespace Models
{
    public class Students_Description
    {
        [Key]
        public int Id { get; set; }
        public int Students_id { get; set; }
        public int age { get; set; }
        public string first_name { get; set; }
        public string last_name { get; set; }
        public string address { get; set; }
        public string country { get; set; }

    }
}