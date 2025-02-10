using System.Threading.Tasks;

namespace BookwormOnline.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string toEmail, string subject, string message);
    }
}
