using System.Text;
using System.Text.Json;
using RabbitMQ.Client;

namespace Services;

public interface IMessageBusService
{
    void PublishUserRegistered(string userId, string email);
}

public class MessageBusService : IMessageBusService, IDisposable
{
    private readonly IConnection _connection;
    private readonly IModel _channel;
    private readonly ILogger<MessageBusService> _logger;
    private const string ExchangeName = "user_events";
    private const string RoutingKeyUserRegistered = "user.registered";

    public MessageBusService(IConfiguration configuration, ILogger<MessageBusService> logger)
    {
        _logger = logger;

        try
        {
            var factory = new ConnectionFactory
            {
                HostName = configuration["RabbitMQ:Host"] ?? "localhost",
                Port = int.Parse(configuration["RabbitMQ:Port"] ?? "5672"),
                UserName = configuration["RabbitMQ:Username"] ?? "guest",
                Password = configuration["RabbitMQ:Password"] ?? "guest"
            };

            _connection = factory.CreateConnection();
            _channel = _connection.CreateModel();

            // Declare exchange
            _channel.ExchangeDeclare(ExchangeName, ExchangeType.Topic, durable: true);

            _logger.LogInformation("RabbitMQ connection established");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to establish RabbitMQ connection");
            throw;
        }
    }

    public void PublishUserRegistered(string userId, string email)
    {
        var message = new
        {
            UserId = userId,
            Email = email,
            Timestamp = DateTime.UtcNow
        };

        var json = JsonSerializer.Serialize(message);
        var body = Encoding.UTF8.GetBytes(json);

        try
        {
            _channel.BasicPublish(
                exchange: ExchangeName,
                routingKey: RoutingKeyUserRegistered,
                basicProperties: null,
                body: body);

            _logger.LogInformation("Published user.registered event for user {UserId}", userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to publish user.registered event for user {UserId}", userId);
            throw;
        }
    }

    public void Dispose()
    {
        _channel?.Dispose();
        _connection?.Dispose();
    }
} 