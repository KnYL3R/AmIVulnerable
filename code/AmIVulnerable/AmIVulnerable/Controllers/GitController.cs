using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
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
                    _ = Clone(CM.AppSettings["StandardCveUrlPlusTag"]!, true);
                    return Ok();
                }
                else {
                    _ = Clone(url, false);
                    return Ok();
                }
            }
            catch (Exception ex) {
                return BadRequest(ex.Message);
            }
        }

        private async Task Clone(string url, bool s){
            await Task.Run(() => {
                if (Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "raw")) {
                    string targetDir = AppDomain.CurrentDomain.BaseDirectory + "raw";
                    RemoveReadOnlyAttribute(targetDir);
                    Directory.Delete(targetDir, true);
                }
                if (s) {
                    Process.Start("git.exe", $"clone {url} --branch cve_2023-12-31_at_end_of_day {AppDomain.CurrentDomain.BaseDirectory}raw");
                }
                else {
                    Process.Start("git.exe", $"clone {url} {AppDomain.CurrentDomain.BaseDirectory}raw");
                }
                #region For Reminder
                //if (s) {
                //    Repository.Clone(url, AppDomain.CurrentDomain.BaseDirectory + "raw", new CloneOptions {
                //        BranchName = "cve_2023-12-31_at_end_of_day",
                //        IsBare = true,
                //    });
                //}
                //else {
                //    Repository.Clone(url, AppDomain.CurrentDomain.BaseDirectory + "raw");
                //}
                #endregion
                CM.AppSettings["CloneFinished"] = "true";
            });
        }

        private void RemoveReadOnlyAttribute(string path) {
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
