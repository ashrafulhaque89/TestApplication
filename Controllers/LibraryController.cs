using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using DTO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Models;
using TestApplication.Data;

namespace Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class LibraryController : ControllerBase
    {
        private readonly Context _context;

        public LibraryController(Context context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Library>>> GetLibraryBooks()
        {
            return await _context.Library.ToListAsync();
        }

        [HttpPost("loan")]
        public async Task<ActionResult<IEnumerable<LoanBookDTO>>> LoanBook(LoanBookDTO request)
        {
            foreach(var item in request.books)
            {
                var library = new Library()
                {
                    Student_id = request.Student_id,
                    Book_id = item,
                    Allocation_date = DateTime.UtcNow,
                    Return_date = null,
                    Renewed = 0
                };
                await _context.Library.AddAsync(library);
                await _context.SaveChangesAsync();
            }

            return CreatedAtAction("GetLibraryBooks",request);
        }

        [HttpPost("return")]
        public async Task<ActionResult<IEnumerable<LoanBookDTO>>> ReturnBook(ReturnBookDTO request)
        {
            foreach(var item in request.Id)
            {
                var library_item = await _context.Library.SingleOrDefaultAsync(x => x.Id == item);
                library_item.Return_date = DateTime.UtcNow;
                await _context.SaveChangesAsync();
            }

            return CreatedAtAction("GetLibraryBooks",request);
        }

        [HttpPost("renew")]
        public async Task<ActionResult<IEnumerable<AddBook>>> Renew(ReturnBookDTO request)
        {
            foreach(var item in request.Id)
            {
                var library_item = await _context.Library.SingleOrDefaultAsync(x => x.Id == item);
                library_item.Renewed = library_item.Renewed + 1;
                await _context.SaveChangesAsync();
            }
            
            return CreatedAtAction("GetLibraryBooks",request);
        }
    }
}