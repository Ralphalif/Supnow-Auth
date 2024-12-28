using System.Net.Mail;
using System.Net;

namespace Services;

public class EmailService(IConfiguration configuration, ILogger<EmailService> logger) : IEmailService
{
    private readonly IConfiguration _configuration = configuration;

    public async Task SendVerificationEmailAsync(string email, string token)
    {
        try
        {
            var smtpSettings = _configuration.GetSection("SmtpSettings");
            var host = smtpSettings["Host"] ?? throw new InvalidOperationException("SMTP Host not configured");
            var port = int.Parse(smtpSettings["Port"] ?? "587");
            var username = smtpSettings["Username"] ?? throw new InvalidOperationException("SMTP Username not configured");
            var password = smtpSettings["Password"] ?? throw new InvalidOperationException("SMTP Password not configured");
            var fromEmail = smtpSettings["FromEmail"] ?? "noreply@supnow.com";
            var fromName = smtpSettings["FromName"] ?? "Supnow Auth";

            var verificationUrl = $"{_configuration["AppUrl"]}/verify-email?token={WebUtility.UrlEncode(token)}";
            
            var message = new MailMessage
            {
                From = new MailAddress(fromEmail, fromName),
                Subject = "Verify your email address",
                Body = $@"
                    <h2>Welcome to Supnow!</h2>
                    <p>Please verify your email address by clicking the link below:</p>
                    <p><a href='{verificationUrl}'>Verify Email</a></p>
                    <p>If you did not create an account, please ignore this email.</p>
                    <p>Best regards,<br>The Supnow Team</p>",
                IsBodyHtml = true
            };
            message.To.Add(email);

            using var client = new SmtpClient(host, port)
            {
                Credentials = new NetworkCredential(username, password),
                EnableSsl = true
            };

            await client.SendMailAsync(message);
            logger.LogInformation($"Verification email sent to {email}");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, $"Failed to send verification email to {email}");
            throw;
        }
    }
} 