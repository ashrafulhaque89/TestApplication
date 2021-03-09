using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using TestApplication.Data;
using TestApplication.DTO;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using TestApplication.Models;
using DTO;

namespace TestApplication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class BooksController : ControllerBase
    {
        private readonly Context _context;

        public BooksController(Context context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<BookDTO>>> GetBooks()
        {
            var book = from books in _context.Book
            join book_descriptions in _context.Book_Description on books.id equals book_descriptions.book_id
            select new BookDTO
            {
                Book_id = books.id,
                Book_price = books.price,
                ISBN = books.isbn,
                Book_name = book_descriptions.book_name,
                Book_description = book_descriptions.book_description
            };

            return await book.ToListAsync();
        }

        [HttpGet("{id}")]
        public ActionResult<BookDTO> GetBooks_byId(int id)
        {
            var book = from books in _context.Book
            join book_descriptions in _context.Book_Description on books.id equals book_descriptions.book_id
            select new BookDTO
            {
                Book_id = books.id,
                Book_price = books.price,
                ISBN = books.isbn,
                Book_name = book_descriptions.book_name,
                Book_description = book_descriptions.book_description
            };

            var book_by_id = book.ToList().Find(x => x.Book_id == id);

            if (book_by_id == null)
            {
                return NotFound();
            }
            return book_by_id;
        }

        [HttpPost]
        public async Task<ActionResult<AddBook>> Add_Books(AddBook bookDTO)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var book = new Book()
            {
                isbn = bookDTO.ISBN,
                price = bookDTO.Book_price
            };
            await _context.Book.AddAsync(book);
            await _context.SaveChangesAsync();

            var book_description = new Book_description()
            {
                book_id = book.id,
                book_name = bookDTO.Book_name,
                book_description = bookDTO.Book_description
            };
            await _context.AddAsync(book_description);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetBooks", new { id = book.id}, bookDTO);
        }

        [HttpDelete("{id}")]
        public async Task<ActionResult<Book>> Delete_Book(int id)
        {
            var book = _context.Book.Find(id);
            var book_description = _context.Book_Description.SingleOrDefault(x => x.book_id == id);

            if(book == null)
            {
                return NotFound();
            }
            else 
            {
                _context.Remove(book);
                _context.Remove(book_description);
                await _context.SaveChangesAsync();
                return book;
            }
        }

        [HttpPut("{id}")]
        public async Task<ActionResult> Update_Books(int id, BookDTO book)
        {
            if(id != book.Book_id || !BookExists(id))
            {
                return BadRequest();
            }
            else 
            {
                var books = _context.Book.SingleOrDefault(x => x.id == id);
                var books_description = _context.Book_Description.SingleOrDefault(x => x.book_id == id);

                books.isbn = book.ISBN;
                books.price = book.Book_price;
                books_description.book_name = book.Book_name;
                books_description.book_description = book.Book_description;
                await _context.SaveChangesAsync();
                return NoContent();
            }
        }

        private bool BookExists(int id)
        {
            return _context.Book.Any(x => x.id == id);
        }
    }
}