using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.VisualStudio.TestPlatform.TestHost;

namespace AmIVulnerable.Test {

    public class UnitTestDemo {

        [Fact]
        public async Task TestDemo() {
            await using var application = new WebApplicationFactory<Program>();
            using var client = application.CreateClient();

        }
    }
}