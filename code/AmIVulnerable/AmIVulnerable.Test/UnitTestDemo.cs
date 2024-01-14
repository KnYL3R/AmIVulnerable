using Microsoft.AspNetCore.Mvc.Testing;
using Newtonsoft.Json;
using System.Net;
using System.Text;

namespace AmIVulnerable.Test {

    public class UnitTestDemo {

        /// <summary>This test send the ping route of the DbTest-Controller and check the positiv result 200 Ok.</summary>
        [Fact]
        public async Task TestDemo() {
            await using var application = new WebApplicationFactory<Program>();
            using (var client = application.CreateClient()) {
                Assert.Equal(HttpStatusCode.OK, client.GetAsync("api/DbTest/ping").Result.StatusCode);
            }
        }

        /// <summary>This test only send a request with the wrong Method and check if the controller answer
        /// with the correct Statuscode, that is not Ok() = 200.</summary>
        [Fact]
        public async Task PingTwoTest() {
            await using var application = new WebApplicationFactory<Program>();
            using (var client = application.CreateClient()) {
                HttpResponseMessage response = await client.PostAsync("api/DbTest/ping", null);

                Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
            }
        }

        /// <summary>This test send a API-request that include a body-string.
        /// After the response, it will check if the content was correct inform if the response is Statuscode
        /// 200 and the returncontent is "Positiv".</summary>
        [Fact]
        public async Task PingWithContent() {
            await using var application = new WebApplicationFactory<Program>();
            using (var client = application.CreateClient()) {
                string jsonToSend = JsonConvert.SerializeObject("DemoDummy");
                HttpRequestMessage request = new HttpRequestMessage() {
                    RequestUri = new Uri("http://localhost/api/DbTest/contentPing"),
                    Content = new StringContent(jsonToSend, Encoding.UTF8, "application/json"),
                    Method = HttpMethod.Post
                };
                Console.WriteLine(request.Content);
                HttpResponseMessage response = await client.SendAsync(request);

                string returnContent = await response.Content.ReadAsStringAsync();

                Assert.True(response.IsSuccessStatusCode && returnContent.Equals("Positiv"));
            }
        }
    }
}