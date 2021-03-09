using Models;

namespace TestApplication.DTO
{
    public class BookDTO : Library
    {
        public decimal Book_price { get; set; }
        public string ISBN { get; set; }
        public string Book_name { get; set; }
        public string Book_description { get; set; }
    }
}