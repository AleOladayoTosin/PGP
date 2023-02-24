using Microsoft.AspNetCore.Mvc;

namespace PGPCore.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "GetWeatherForecast")]
        public IEnumerable<WeatherForecast> Get()
        {
            //Pgp.EncryptFile(@"C:/PGP/Output/output.txt", @"C:/PGP/FIle/enrol-success.txt", @"C:/PGP/Key/0x23B860DC-pub.asc", true, true);

            Pgp.DecryptFile(@"C:/PGP/Output/output.txt", @"C:/PGP/Key/0x23B860DC-sec.asc", "password".ToCharArray(), @"C:/PGP/Output/");
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}