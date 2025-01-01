using System.Text;
using System.Text.Json;
using RabbitMQ.Client;

namespace Services;

public interface IMessageBusService
{
    void PublishUserRegistered(string userId, string username, string email);
}

public class MessageBusService : IMessageBusService, IDisposable
{
    private readonly IConnection _connection;
    private readonly IModel _channel;
    private readonly ILogger<MessageBusService> _logger;
    private const string ExchangeName = "user_events";
    private const string RoutingKeyUserRegistered = "user.registered";
    private const string QueueName = "user_created";

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

            _logger.LogInformation("RabbitMQ connection established. Configuring exchange and queue...");

            try
            {
                // Declare exchange
                _logger.LogInformation("Declaring exchange: {ExchangeName} of type {ExchangeType}", ExchangeName, ExchangeType.Topic);
                _channel.ExchangeDeclare(
                    exchange: ExchangeName,
                    type: ExchangeType.Topic,
                    durable: true,
                    autoDelete: false,
                    arguments: null);

                // Declare queue with more explicit configuration
                _logger.LogInformation("Declaring queue: {QueueName}", QueueName);
                var queueDeclareResult = _channel.QueueDeclare(
                    queue: QueueName,
                    durable: true,
                    exclusive: false,
                    autoDelete: false,
                    arguments: new Dictionary<string, object>
                    {
                        { "x-queue-type", "classic" }
                    });

                _logger.LogInformation("Queue declared successfully. Queue info - Messages: {MessageCount}, Consumers: {ConsumerCount}",
                    queueDeclareResult.MessageCount,
                    queueDeclareResult.ConsumerCount);

                // Bind queue to exchange
                _logger.LogInformation("Binding queue {QueueName} to exchange {ExchangeName} with routing key {RoutingKey}",
                    QueueName, ExchangeName, RoutingKeyUserRegistered);

                _channel.QueueBind(
                    queue: QueueName,
                    exchange: ExchangeName,
                    routingKey: RoutingKeyUserRegistered);

                _logger.LogInformation("RabbitMQ configuration completed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to configure RabbitMQ exchange and queue");
                throw;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to establish RabbitMQ connection");
            throw;
        }
    }

    public void PublishUserRegistered(string userId, string username, string email)
    {
        var message = new
        {
            Id = userId,
            Username = username,
            Email = email
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