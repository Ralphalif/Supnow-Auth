using Microsoft.Extensions.Hosting;

namespace Supnow.Api.Services.MessageBus;

public class MessageConsumerHostedService : IHostedService
{
    private readonly IMessageConsumer _messageConsumer;
    private readonly ILogger<MessageConsumerHostedService> _logger;

    public MessageConsumerHostedService(
        IMessageConsumer messageConsumer,
        ILogger<MessageConsumerHostedService> logger)
    {
        _messageConsumer = messageConsumer;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _messageConsumer.StartConsumingAsync();
            _logger.LogInformation("Message consumer started");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting message consumer");
            throw;
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _messageConsumer.StopConsumingAsync();
            _logger.LogInformation("Message consumer stopped");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping message consumer");
            throw;
        }
    }
} 