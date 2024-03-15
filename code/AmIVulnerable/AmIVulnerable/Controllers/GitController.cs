using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using CM = System.Configuration.ConfigurationManager;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class GitController : ControllerBase {

        /// <summary>
        /// API-Post route to clone a git repository
        /// </summary>
        /// <param name="cveRaw">Use raw cve data.</param>
        /// <param name="data">Tuple of url and tag.</param>
        /// <returns>OK if successful. BadRequest if error when cloning.</returns>
        [HttpPost]
        [Route("clone")]
        public IActionResult CloneRepo([FromHeader] bool cveRaw, [FromBody] Tuple<string, string> data) {
        //public IActionResult CloneRepo([FromHeader] string? url) {
            try {
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

        /// <summary>
        /// Clone a git repository.
        /// </summary>
        /// <param name="url">URL of git project to clone.</param>
        /// <param name="tag">Tag of git project.</param>
        /// <param name="dir">Directory where to clone project into.</param>
        /// <returns></returns>
        private static async Task Clone(string url, string tag, string dir){
            try {
                await Task.Run(() => {
                    if (Directory.Exists(dir)) {
                        RemoveReadOnlyAttribute(dir);
                        Directory.Delete(dir, true);
                    }
                    if (tag.Equals("")) {
                        Process.Start("git", $"clone {url} {dir}");
                    }
                    else {
                        try {
                            Process.Start("git", $"clone {url} --branch {tag} {dir}");
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
                });
            }
            catch (Exception ex) {
                await Console.Out.WriteLineAsync(ex.StackTrace);
            }
        }

        /// <summary>
        /// Removes read only access of files.
        /// </summary>
        /// <param name="path">File path to folder where all read only attributes of files need to be removed.</param>
        private static void RemoveReadOnlyAttribute(string path) {
            DirectoryInfo directoryInfo = new DirectoryInfo(path);

            foreach (FileInfo file in directoryInfo.GetFiles()) {
                file.Attributes &= ~FileAttributes.ReadOnly;
            }

            foreach (DirectoryInfo subDirectory in directoryInfo.GetDirectories()) {
                RemoveReadOnlyAttribute(subDirectory.FullName);
            }
        }
    }
}
