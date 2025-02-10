using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using BookwormOnline.Model;
using Microsoft.AspNetCore.Authorization;

namespace BookwormOnline.Pages
{
    [Authorize(Roles = "Admin,User")]
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _db;
        private readonly ILogger<LogoutModel> _logger;

        public LogoutModel(SignInManager<ApplicationUser> signInManager, AuthDbContext db, ILogger<LogoutModel> logger)
        {
            _signInManager = signInManager;
            _db = db;
            _logger = logger;
        }

        public async Task<IActionResult> OnGet()
        {
            try
            {
                var userEmail = User.Identity?.Name;

                if (!string.IsNullOrEmpty(userEmail))
                {
                    // Log the logout action
                    _db.AuditLogs.Add(new AuditLog
                    {
                        UserEmail = userEmail,
                        Action = "Logout",
                        Timestamp = DateTime.UtcNow
                    });

                    await _db.SaveChangesAsync();
                    _logger.LogInformation("User {Email} logged out successfully.", userEmail);
                }
                else
                {
                    _logger.LogWarning("Logout attempt with no user session.");
                }

                await _signInManager.SignOutAsync();
                HttpContext.Session.Clear();

                return RedirectToPage("/Login");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during logout.");
                return RedirectToPage("/Error/500");
            }
        }
    }
}
