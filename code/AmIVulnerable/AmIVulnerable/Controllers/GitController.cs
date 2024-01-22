using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using CM = System.Configuration.ConfigurationManager;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class GitController : ControllerBase {

        [HttpPost]
        [Route("clone")]
        public IActionResult CloneRepo([FromHeader] bool cveRaw, [FromBody] Tuple<string, string> data) {
        //public IActionResult CloneRepo([FromHeader] string? url) {
            try {
                CM.AppSettings["CloneFinished"] = "false";
                if (cveRaw) {
                    if (data.Item1.Equals("")) { // nothing, so use standard
                        if (data.Item2.Equals("")) { //nothing, so use standard
                            _ = Clone(CM.AppSettings["StandardCveUrlPlusTag"]!, "cve_2023-12-31_at_end_of_day", "raw");

                        }
                        else {
                            _ = Clone(CM.AppSettings["StandardCveUrlPlusTag"]!, data.Item2, "raw");
                        }
                    }
                    else {
                        _ = Clone(data.Item1, data.Item2, "raw");
                    }
                }
                else {
                    _ = Clone(data.Item1, data.Item2, "rawAnalyze");
                }
                return Ok();
            }
            catch (Exception ex) {
                return BadRequest(ex.Message);
            }
        }

        private static async Task Clone(string url, string tag, string dir){
            await Task.Run(() => {
                if (Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + dir)) {
                    string targetDir = AppDomain.CurrentDomain.BaseDirectory + dir;
                    RemoveReadOnlyAttribute(targetDir);
                    Directory.Delete(targetDir, true);
                }
                if (tag.Equals("")) {
                    Process.Start("git.exe", $"clone {url} {AppDomain.CurrentDomain.BaseDirectory}{dir}");
                }
                else {
                    try {
                        Process.Start("git.exe", $"clone {url} --branch {tag} {AppDomain.CurrentDomain.BaseDirectory}{dir}");
                    }
                    catch (Exception ex) {
                        Console.WriteLine("Error with clone, tag?\n" + ex.Message);
                        return; // leave CloneFinished false
                    }
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

        private static void RemoveReadOnlyAttribute(string path) {
            DirectoryInfo directoryInfo = new DirectoryInfo(path);

            foreach (FileInfo file in directoryInfo.GetFiles()) {
                file.Attributes &= ~FileAttributes.ReadOnly;
            }

            foreach (DirectoryInfo subDirectory in directoryInfo.GetDirectories()) {
                RemoveReadOnlyAttribute(subDirectory.FullName);
            }
        }

        [HttpGet]
        [Route("cloneStatus")]
        public IActionResult CloneStatus() {
            if (CM.AppSettings["CloneFinished"]!.Equals("true")) {
                return Ok();
            }
            else {
                return NoContent();
            }
        }
    }
}
