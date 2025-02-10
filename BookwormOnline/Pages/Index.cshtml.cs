using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BookwormOnline.Model;
using Microsoft.Extensions.Configuration;

namespace BookwormOnline.Pages
{
    public class IndexModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<IndexModel> _logger;

        public ApplicationUser CurrentUser { get; set; }

        public IndexModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration, ILogger<IndexModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<IActionResult> OnGet()
        {
            try
            {
                bool usersExist = _userManager.Users.Any();

                if (!usersExist)
                {
                    _logger.LogWarning("No users found. Redirecting to Register page.");
                    return RedirectToPage("/Register");
                }

                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                {
                    _logger.LogWarning("User session invalid. Redirecting to Login page.");
                    return RedirectToPage("/Login");
                }

                Console.WriteLine($"User: {user.PhotoPath}");
                _logger.LogInformation($"User {user.Email} accessed Index page.");

                string storedToken = HttpContext.Session.GetString("SessionToken");
                if (string.IsNullOrEmpty(storedToken) || user.SessionToken != storedToken)
                {
                    _logger.LogWarning($"Session token mismatch for user {user.Email}. Logging out.");
                    await _signInManager.SignOutAsync();
                    HttpContext.Session.Clear();
                    return RedirectToPage("/Login");
                }

                CurrentUser = user;

                // Decrypt and display sensitive data
                ViewData["DecryptedCreditCard"] = DecryptData(user.CreditCardNo);

                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error occurred on Index page.");
                return RedirectToPage("/Errors/500");
            }
        }

        private string DecryptData(string encryptedText)
        {
            try
            {
                byte[] encryptionKey = Convert.FromBase64String(_configuration["EncryptionSettings:AESKey"]);
                byte[] iv = Convert.FromBase64String(_configuration["EncryptionSettings:AESIV"]);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = encryptionKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    {
                        byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                        byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                        return Encoding.UTF8.GetString(decryptedBytes);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Decryption failed.");
                return "Decryption Error";
            }
        }
    }
}
