using System.Threading.Tasks;

namespace Supnow.Api.Services.MessageBus;

public interface IMessageConsumer
{
    Task StartConsumingAsync();
    Task StopConsumingAsync();
} 