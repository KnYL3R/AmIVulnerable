using LibGit2Sharp;
using Microsoft.AspNetCore.Mvc;
using CM = System.Configuration.ConfigurationManager;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class GitController : ControllerBase {

        [HttpGet]
        [Route("clone")]
        public IActionResult CloneRepo([FromHeader] string? url) {
            try {
                CM.AppSettings["CloneFinished"] = "false";
                if (url.Equals("s")) {
                    _ = Clone(CM.AppSettings["StandardCveUrlPlusTag"]!);
                    return Ok();
                }
                else {
                    _ = Clone(url);
                    return Ok();
                }
            }
            catch (Exception ex) {
                return BadRequest(ex.Message);
            }
        }

        private async Task Clone(string url){
            await Task.Run(() => {
                Repository.Clone(url, AppDomain.CurrentDomain.BaseDirectory + "raw");
                CM.AppSettings["CloneFinished"] = "true";
            });
        }
    }
}
