using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TestApplication.Data;
using TestApplication.Models;

namespace TestApplication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ValuesController : ControllerBase
    {
        private readonly Context _context;
        public ValuesController(Context context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Values>>> GetValues()
        {
            return await _context.Values.ToListAsync();
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<Values>> GetValues_ById(int id)
        {
            var values = await _context.Values.FindAsync(id);
            if(values != null)
            {
                return values;
            }
            else
            {
                return NotFound();
            }
        }

        [HttpPost]
        public async Task<ActionResult<Values>> Post_Values(Values values)
        {
            _context.Values.Add(values);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetValues", new { id = values.Id }, values);
        }

        [HttpDelete("{id}")]
        public async Task<ActionResult<Values>> Delete_values(int id)
        {
            var values = await _context.Values.FindAsync(id);
            if (values == null)
            {
                return NotFound();
            }

            _context.Values.Remove(values);
            await _context.SaveChangesAsync();

            return values;
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Put_Values(int id, Values values)
        {
            if (id != values.Id)
            {
                return BadRequest();
            }

            _context.Entry(values).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!ValuesExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        private bool ValuesExists(int id)
        {
            return _context.Values.Any(e => e.Id == id);
        }
    }
}