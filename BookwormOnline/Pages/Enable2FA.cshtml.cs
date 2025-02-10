using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using BookwormOnline.Model;

namespace BookwormOnline.Pages
{
    public class Enable2FAModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<Enable2FAModel> _logger;

        public Enable2FAModel(UserManager<ApplicationUser> userManager, ILogger<Enable2FAModel> logger)
        {
            _userManager = userManager;
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

            return RedirectToPage("/Index");
        }
    }
}
