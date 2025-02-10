using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using BookwormOnline.Model;
using System.Collections.Generic;
using System.Linq;

namespace BookwormOnline.Pages
{
    [Authorize(Roles = "Admin")]
    public class AuditLogsModel : PageModel
    {
        private readonly AuthDbContext _context;

        public AuditLogsModel(AuthDbContext context)
        {
            _context = context;
        }

        public List<AuditLog> AuditLogs { get; set; }

        public void OnGet()
        {
            AuditLogs = _context.AuditLogs.ToList();
        }
    }
}
