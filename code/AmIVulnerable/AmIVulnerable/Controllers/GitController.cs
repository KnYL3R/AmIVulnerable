using LibGit2Sharp;
using Microsoft.AspNetCore.Mvc;
using System.Security.AccessControl;
using static System.Runtime.InteropServices.JavaScript.JSType;
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
                if (Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "raw")) {
                    string targetDir = AppDomain.CurrentDomain.BaseDirectory + "raw";
                    RemoveReadOnlyAttribute(targetDir);
                    Directory.Delete(targetDir, true);
                }
                Repository.Clone(url, AppDomain.CurrentDomain.BaseDirectory + "raw");
                CM.AppSettings["CloneFinished"] = "true";
            });
        }

        public void RemoveReadOnlyAttribute(string path) {
            DirectoryInfo directoryInfo = new DirectoryInfo(path);

            foreach (var file in directoryInfo.GetFiles()) {
                file.Attributes &= ~FileAttributes.ReadOnly;
            }

            foreach (var subDirectory in directoryInfo.GetDirectories()) {
                RemoveReadOnlyAttribute(subDirectory.FullName);
            }
        }

        [HttpGet]
        [Route("cloneStatus")]
        public IActionResult CloneStatus() {
            if (CM.AppSettings["CloneFinished"].Equals("true")) {
                return Ok();
            }
            else {
                return NoContent();
            }
        }
    }
}
