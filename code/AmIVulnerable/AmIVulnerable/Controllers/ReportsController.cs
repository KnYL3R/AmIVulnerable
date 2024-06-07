using Microsoft.AspNetCore.Mvc;
using Modells;
using Modells.Packages;
using MySql.Data.MySqlClient;
using System.Data;
using System.Diagnostics;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class ReportsController : ControllerBase {

        #region Config

        private readonly IConfiguration Configuration;
        public ReportsController(IConfiguration configuration) {
            Configuration = configuration;
        }

        #endregion

        #region Controller

        /// <summary>
        /// Generate a SimpleReport for a list of Projects
        /// </summary>
        /// <param name="mavenList"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("simpleAnalyseNpmList")]
        public async Task<IActionResult> SimpleAnalyseNpmList([FromBody] List<Modells.Project> npmList) {
            List<SimpleReportLine> simpleReport = [];
            foreach (Modells.Project npm in npmList) {
                string dirGuid = await CloneProject(npm);
                if (dirGuid.Equals("Err")) {
                    return BadRequest("Could not clone project!");
                }
                foreach(string tag in npm.Tags) {
                    CheckoutTagProject(tag, dirGuid);
                    List<PackageResult> depTreeRelease = AnalyseTree(ExtractTree(MakeTree(dirGuid)), "release");
                    List<PackageResult> depTreeCurrent = AnalyseTree(ExtractTree(MakeTree(dirGuid)), "current");
                    simpleReport.Add(GenerateSimpleReportLine(depTreeRelease, depTreeCurrent));
                }
                DeleteProject(dirGuid);
            }
            return Ok(simpleReport);
        }

        #endregion

        #region Internal function(s)

        /// <summary>
        /// 
        /// </summary>
        /// <param name="npm"></param>
        private async Task<string> CloneProject(Modells.Project npm) {
            if (npm.ProjectUrl is null) {
                return "Err";
            }

            else { // clone the repo
                Guid repoId = Guid.NewGuid();
                string trimmedUrl = npm.ProjectUrl[(npm.ProjectUrl.IndexOf("//") + 2)..(npm.ProjectUrl.Length)];
                trimmedUrl = trimmedUrl[(trimmedUrl.IndexOf('/') + 1)..(trimmedUrl.Length)];
                string owner = trimmedUrl[0..trimmedUrl.IndexOf('/', 1)];
                string designation = trimmedUrl[(owner.Length + 1)..trimmedUrl.Length];
                if (designation.Contains('/')) {
                    designation = designation[0..trimmedUrl.IndexOf('/', owner.Length + 1)];
                }

                ExecuteMySqlCommand($"" +
                    $"INSERT INTO cve.repositories (guid, repoUrl, repoOwner, repoDesignation) " +
                    $"VALUES (" +
                    $"'{repoId}'," +
                    $"'{npm.ProjectUrl}'," +
                    $"'{owner}'," +
                    $"'{designation});");

                await Clone(npm.ProjectUrl, repoId.ToString());
                return repoId.ToString();
            }
        }

        /// <summary>
        /// Clone a git repository.
        /// </summary>
        /// <param name="url">URL of git project to clone.</param>
        /// <param name="tag">Tag of git project.</param>
        /// <param name="dir">Directory where to clone project into.</param>
        /// <returns></returns>
        private static async Task Clone(string url, string dir) {
            try {
                await Task.Run(() => {
                    if (Directory.Exists(dir)) {
                        RemoveReadOnlyAttribute(dir);
                        Directory.Delete(dir, true);
                    }
                    Process.Start("git", $"clone {url} {dir}");
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

        private DataTable ExecuteMySqlCommand(string command) {
            // MySql Connection
            MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);
            MySqlCommand cmd = new MySqlCommand(command, connection);
            DataTable dataTable = new DataTable();
            connection.Open();

            MySqlDataReader reader = cmd.ExecuteReader();
            dataTable.Load(reader);
            connection.Close();
            return dataTable;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tag"></param>
        private bool CheckoutTagProject(string tag, string dir) {
            try {
                ProcessStartInfo process = new ProcessStartInfo {
                    FileName = "bash",
                    RedirectStandardInput = true,
                    WorkingDirectory = $"{dir}",
                };

                Process runProcess = Process.Start(process)!;
                runProcess.StandardInput.WriteLine($"git " + $"checkout {tag}");
                runProcess.StandardInput.WriteLine($"exit");
                runProcess.WaitForExit();

                return true;
            }
            catch (Exception ex) {
                Console.WriteLine("Error with clone, tag?\n" + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dir"></param>
        private void DeleteProject(string dir) {
            if(Directory.Exists(dir)) {
                RemoveReadOnlyAttribute(dir);
                Directory.Delete(dir, true);

                //dir is guid (folder named after guid)
                ExecuteMySqlCommand($"DELETE FROM cve.repositories WHERE guid LIKE '{dir}';");
            }
        }

        /// <summary>
        /// Make a tree.json file
        /// </summary>
        /// <param name="projectUrl"></param>
        /// <param name="Tag"></param>
        /// <returns>File path</returns>
        private string MakeTree(string dirGuid) {
            ExecuteCommand("npm", "install", dirGuid);
            ExecuteCommand("rm", "tree.json", dirGuid);
            ExecuteCommand("npm", "list --all --json >> tree.json", dirGuid);
            return "/tree.json";
        }

        /// <summary>
        /// Extract internal representation of tree from tree.json
        /// </summary>
        /// <param name="treeFilePath"></param>
        /// <returns></returns>
        private List<Package> ExtractTree(string treeFilePath) {
            //dirGuid + treeFilePath
            //Use absolute Path for finding tree.json
            return [];
        }

        /// <summary>
        /// Check Package list agains cve data, differentiate between current cve database and past versions through cveVersion
        /// </summary>
        /// <param name="packageList"></param>
        /// <param name="cveVersion"></param>
        /// <returns></returns>
        private List<PackageResult> AnalyseTree(List<Package> packageList, string cveVersion) {
            if(cveVersion == "release") {
                //Get all dependencies with depth (0 = direct, 1= 1st degree transitive, 2= 2nd degree...)
                //Get number of subdependencies for every dependency
                return [];

            } else if(cveVersion == "current") {
                return [];
            }
            else {
                return [];
            }
            //Needs to compare designations AND versions of Used Packages with Cve
            //Compare on cve database at the time AND
            //Compare on cve database now
        }

        private SimpleReportLine GenerateSimpleReportLine(List<PackageResult> releaseVulnerabilitiesList, List<PackageResult> currentVulnerabilitiesList) {
            return new SimpleReportLine();
        }

        /// <summary>
        /// Starts a process that runs a command.
        /// </summary>
        /// <param name="prog">Programm used for commands</param>
        /// <param name="command">Command used for programm</param>
        private void ExecuteCommand(string prog, string command, string dir) {
            ProcessStartInfo process = new ProcessStartInfo {
                FileName = "cmd",
                RedirectStandardInput = true,
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory + dir,
            };
            Process runProcess = Process.Start(process)!;
            runProcess.StandardInput.WriteLine($"{prog} {command}");
            runProcess.StandardInput.WriteLine($"exit");
            runProcess.WaitForExit();
        }

        #endregion
    }

}
