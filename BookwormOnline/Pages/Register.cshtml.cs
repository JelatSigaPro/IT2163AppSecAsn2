using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BookwormOnline.Model;
using System.Net;

namespace BookwormOnline.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<RegisterModel> _logger;

        [BindProperty]
        public Register RModel { get; set; }

        private readonly byte[] encryptionKey;
        private readonly byte[] iv;

        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration, ILogger<RegisterModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _logger = logger;

            encryptionKey = Convert.FromBase64String(_configuration["EncryptionSettings:AESKey"]);
            iv = Convert.FromBase64String(_configuration["EncryptionSettings:AESIV"]);
        }

        public void OnGet()
        {
            try
            {
                if (!_userManager.Users.Any())
                {
                    ViewData["ShowAdminRegisterMessage"] = "No users found. Please register an admin account.";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while checking existing users.");
                RedirectToPage("/Errors/500");
            }
        }

        private string EncodeInput(string input)
        {
            return WebUtility.HtmlEncode(input);
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

                var existingUser = await _userManager.FindByEmailAsync(RModel.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError("RModel.Email", "Email is already taken.");
                    return Page();
                }

                string photoPath = null;
                if (RModel.Photo != null)
                {
                    try
                    {
                        var extension = Path.GetExtension(RModel.Photo.FileName).ToLower();
                        if (extension != ".jpg")
                        {
                            ModelState.AddModelError("RModel.Photo", "Only .JPG files are allowed.");
                            return Page();
                        }

                        var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads");
                        Directory.CreateDirectory(uploadsFolder);
                        string uniqueFileName = Guid.NewGuid().ToString() + extension;
                        string filePath = Path.Combine(uploadsFolder, uniqueFileName);

                        using (var fileStream = new FileStream(filePath, FileMode.Create))
                        {
                            await RModel.Photo.CopyToAsync(fileStream);
                        }

                        photoPath = "/uploads/" + uniqueFileName;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error uploading profile photo.");
                        ModelState.AddModelError("RModel.Photo", "Error uploading the profile picture.");
                        return Page();
                    }
                }

                // Encode all user inputs before storing in the database
                string encodedFirstName = EncodeInput(RModel.FirstName);
                string encodedLastName = EncodeInput(RModel.LastName);
                string encodedBillingAddress = EncodeInput(RModel.BillingAddress);
                string encodedShippingAddress = EncodeInput(RModel.ShippingAddress);

                string hashedPassword = HashPassword(RModel.Password);
                string encryptedCreditCard = EncryptData(RModel.CreditCardNo);
                string sessionToken = GenerateSessionToken();

                var user = new ApplicationUser
                {
                    FirstName = encodedFirstName,
                    LastName = encodedLastName,
                    CreditCardNo = encryptedCreditCard,
                    MobileNo = RModel.MobileNo,
                    BillingAddress = encodedBillingAddress,
                    ShippingAddress = encodedShippingAddress,
                    Email = EncodeInput(RModel.Email),
                    UserName = EncodeInput(RModel.Email),
                    PhotoPath = photoPath,
                    PasswordHash = hashedPassword,
                    SessionToken = sessionToken
                };

                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    HttpContext.Session.SetString("SessionToken", sessionToken);
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation("New user {Email} registered successfully.", user.Email);
                    return RedirectToPage("Index");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during user registration.");
                return RedirectToPage("/Errors/500");
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

        private string EncryptData(string plainText)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = encryptionKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    {
                        byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                        byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                        return Convert.ToBase64String(encryptedBytes);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Encryption failed.");
                return "EncryptionError";
            }
        }
    }
}
