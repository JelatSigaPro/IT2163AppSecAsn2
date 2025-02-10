using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using BookwormOnline.Model;
using Microsoft.AspNetCore.Authorization;

namespace BookwormOnline.Pages
{
    [Authorize(Roles = "Admin,User")]
    public class Enable2FAModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly ILogger<Enable2FAModel> _logger;

        public Enable2FAModel(UserManager<ApplicationUser> userManager, AuthDbContext db, ILogger<Enable2FAModel> logger)
        {
            _userManager = userManager;
            _db = db;
            _logger = logger;
        }

        public async Task<IActionResult> OnPostEnable2FAAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            user.Is2FAEnabled = true;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User enabled 2FA.");

            // Log enabling 2FA
            _db.AuditLogs.Add(new AuditLog
            {
                UserEmail = user.Email,
                Action = "Enabled 2FA",
                Timestamp = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            return RedirectToPage("/Index");
        }

        public async Task<IActionResult> OnPostDisable2FAAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            user.Is2FAEnabled = false;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User disabled 2FA.");

            // Log disabling 2FA
            _db.AuditLogs.Add(new AuditLog
            {
                UserEmail = user.Email,
                Action = "Disabled 2FA",
                Timestamp = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            return RedirectToPage("/Index");
        }
    }
}

