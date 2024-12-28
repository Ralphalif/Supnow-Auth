using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace Supnow.Api.Services.MessageBus;

public class RabbitMQConsumer : IMessageConsumer, IDisposable
{
    private readonly IConnection _connection;
    private readonly IModel _channel;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<RabbitMQConsumer> _logger;
    private const string ExchangeName = "user_events";
    private const string QueueName = "main_service_user_queue";
    private const string RoutingKeyUserRegistered = "user.registered";

    public RabbitMQConsumer(
        IConfiguration configuration,
        IServiceProvider serviceProvider,
        ILogger<RabbitMQConsumer> logger)
    {
        _serviceProvider = serviceProvider;
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

            // Declare queue
            _channel.QueueDeclare(QueueName, durable: true, exclusive: false, autoDelete: false);

            // Bind queue to exchange
            _channel.QueueBind(QueueName, ExchangeName, RoutingKeyUserRegistered);

            _logger.LogInformation("RabbitMQ connection established");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to establish RabbitMQ connection");
            throw;
        }
    }

    public Task StartConsumingAsync()
    {
        var consumer = new EventingBasicConsumer(_channel);
        consumer.Received += async (model, ea) =>
        {
            try
            {
                var body = ea.Body.ToArray();
                var message = Encoding.UTF8.GetString(body);
                var userEvent = JsonSerializer.Deserialize<UserRegisteredEvent>(message);

                if (userEvent != null)
                {
                    using var scope = _serviceProvider.CreateScope();
                    // Here you would get your user service and handle the event
                    // var userService = scope.ServiceProvider.GetRequiredService<IUserService>();
                    // await userService.HandleUserRegisteredAsync(userEvent);
                    
                    _logger.LogInformation("Processed user registration for {UserId}", userEvent.UserId);
                }

                _channel.BasicAck(ea.DeliveryTag, false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing message");
                _channel.BasicNack(ea.DeliveryTag, false, true);
            }
        };

        _channel.BasicConsume(queue: QueueName,
                            autoAck: false,
                            consumer: consumer);

        return Task.CompletedTask;
    }

    public Task StopConsumingAsync()
    {
        _channel?.Close();
        _connection?.Close();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _channel?.Dispose();
        _connection?.Dispose();
    }
}

public class UserRegisteredEvent
{
    public string UserId { get; set; }
    public string Email { get; set; }
    public DateTime Timestamp { get; set; }
} 