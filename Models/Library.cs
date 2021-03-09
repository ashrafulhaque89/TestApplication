using System;
using System.ComponentModel.DataAnnotations;

namespace Models
{
    public class Library
    {
        [Key]
        public int Id { get; set; }
        public int Student_id { get; set; }
        public int Book_id { get; set; }
        public DateTime Allocation_date { get; set; }
        public DateTime? Return_date { get; set; }
        public int Renewed { get; set; }
    }
}