using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace BookwormOnline.Pages
{
    public class ErrorModel : PageModel
    {
        private readonly ILogger<ErrorModel> _logger;

        public int? StatusCode { get; private set; }

        public ErrorModel(ILogger<ErrorModel> logger)
        {
            _logger = logger;
        }

        public void OnGet(int? statusCode)
        {
            StatusCode = statusCode;
            if (statusCode.HasValue)
            {
                _logger.LogError($"An error occurred. Status code: {statusCode}");
            }
            else
            {
                _logger.LogError("An unexpected error occurred.");
            }
        }
    }
}
