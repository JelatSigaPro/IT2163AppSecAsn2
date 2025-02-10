using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BookwormOnline.Model;
using BookwormOnline.ViewModels;
using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace BookwormOnline.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly ILogger<LoginModel> _logger;

        [BindProperty]
        public LoginViewModel LModel { get; set; }

        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext db, ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
            _logger = logger;
        }

        public void OnGet()
        {
        }

        [ValidateAntiForgeryToken] // Enforce CSRF protection
        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return Page();
                }

                // Validate reCAPTCHA token
                string recaptchaToken = Request.Form["g-recaptcha-response"];
                if (string.IsNullOrEmpty(recaptchaToken) || !await ValidateRecaptcha(recaptchaToken))
                {
                    _logger.LogWarning("reCAPTCHA validation failed for {Email}", LModel.Email);
                    ModelState.AddModelError("", "reCAPTCHA failed. Please try again.");
                    return Page();
                }

                var user = await _userManager.FindByEmailAsync(LModel.Email);
                _logger.LogInformation("Login attempt for user: {Email}", user?.Email ?? "User not found");

                if (user == null)
                {
                    _logger.LogWarning("Login failed for {Email}: User not found", LModel.Email);
                    ModelState.AddModelError("", "Invalid credentials.");
                    return Page();
                }

                if (await _userManager.IsLockedOutAsync(user))
                {
                    _logger.LogWarning("Locked out user {Email} attempted login.", user.Email);
                    ModelState.AddModelError("", "Too many failed login attempts. Your account is locked for 5 minutes.");
                    return Page();
                }

                string enteredPasswordHash = HashPassword(LModel.Password);
                if (enteredPasswordHash != user.PasswordHash)
                {
                    await _userManager.AccessFailedAsync(user);
                    int attemptsLeft = 3 - await _userManager.GetAccessFailedCountAsync(user);

                    if (attemptsLeft <= 0)
                    {
                        await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(5));
                        _logger.LogWarning("User {Email} is locked out due to multiple failed attempts.", user.Email);
                        ModelState.AddModelError("", "Too many failed login attempts. Your account is locked for 5 minutes.");
                    }
                    else
                    {
                        _logger.LogWarning("Invalid credentials for {Email}. {AttemptsLeft} attempt(s) left.", user.Email, attemptsLeft);
                        ModelState.AddModelError("", $"Invalid credentials. {attemptsLeft} attempt(s) left.");
                    }
                    return Page();
                }

                await _userManager.ResetAccessFailedCountAsync(user);

                _db.AuditLogs.Add(new AuditLog
                {
                    UserEmail = user.Email,
                    Action = "Login",
                    Timestamp = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                string newSessionToken = GenerateSessionToken();
                if (!string.IsNullOrEmpty(user.SessionToken))
                {
                    await _userManager.UpdateSecurityStampAsync(user);
                }

                user.SessionToken = newSessionToken;
                await _userManager.UpdateAsync(user);
                HttpContext.Session.SetString("SessionToken", newSessionToken);

                await _signInManager.SignInAsync(user, isPersistent: false);
                _logger.LogInformation("User {Email} logged in successfully.", user.Email);

                return RedirectToPage("Index");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during login for {Email}", LModel.Email);
                return RedirectToPage("/Errors/500");
            }
        }


        private async Task<bool> ValidateRecaptcha(string token)
        {
            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.PostAsync($"https://www.google.com/recaptcha/api/siteverify?secret=6LfKG9EqAAAAAOAP8hiLKyk3zTOVsYfIAuyiikzs&response={token}", null);
                var jsonResponse = await response.Content.ReadAsStringAsync();

                Console.WriteLine("reCAPTCHA Response: " + jsonResponse); // Debugging
                var recaptchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);

                if (!recaptchaResult.success)
                {
                    Console.WriteLine("?? reCAPTCHA validation failed!");
                }
                else
                {
                    Console.WriteLine("? reCAPTCHA validation succeeded with score: " + recaptchaResult.score);
                }

                return recaptchaResult.success && recaptchaResult.score >= 0.5;
            }
        }

        // Model for parsing JSON response
        private class RecaptchaResponse
        {
            public bool success { get; set; }
            public float score { get; set; }
            public string action { get; set; }
            public string challenge_ts { get; set; }
            public string hostname { get; set; }
        }



        // SHA-512 Hashing (Same as Registration)
        private string HashPassword(string password)
        {
            try
            {
                using (SHA512 sha512 = SHA512.Create())
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(password);
                    byte[] hashedBytes = sha512.ComputeHash(inputBytes);
                    return Convert.ToBase64String(hashedBytes);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing password.");
                return "HashError";
            }
        }

        private string GenerateSessionToken()
        {
            try
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    byte[] tokenBytes = new byte[32];
                    rng.GetBytes(tokenBytes);
                    return Convert.ToBase64String(tokenBytes);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate session token.");
                return "SessionError";
            }
        }
    }
}
