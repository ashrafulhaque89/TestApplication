using System.Collections.Generic;
using Models;
using TestApplication.DTO;

namespace DTO
{
    public class StudentDetailsDTO : StudentDTO
    {
        public List<BookDTO> Books { get; set; }
    }
}