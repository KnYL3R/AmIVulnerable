using Microsoft.AspNetCore.Mvc;
using Modells;
using MySql.Data.MySqlClient;
using Newtonsoft.Json;
using SerilogTimings;
using System.Data;
using System.Diagnostics;
using System.Text.RegularExpressions;
using CM = System.Configuration.ConfigurationManager;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class GitController : ControllerBase {

        #region Config
        /// <summary></summary>
        private readonly IConfiguration Configuration;

        /// <summary></summary>
        /// <param name="configuration"></param>
        public GitController(IConfiguration configuration) {
            Configuration = configuration;
        }
        #endregion

        #region Controller

        /// <summary></summary>
        /// <param name="repoObject"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("cloneRepo")]
        public async Task<IActionResult> CloneRepoToAnalyze([FromBody] RepoObject repoObject) {
            if (repoObject.RepoUrl is null) {
                return BadRequest();
            }

            // check if repo already cloned
            DataTable tempTable = ExecuteMySqlCommand($"" +
                $"SELECT * " +
                $"FROM cve.repositories " +
                $"WHERE repoUrl='{repoObject.RepoUrl}' AND tag='{repoObject.RepoTag}';");

            if (tempTable.Rows.Count > 0) {
                return Ok(tempTable.Rows[0]["guid"]);
            }
            else { // clone the repo
                Guid repoId = Guid.NewGuid();
                string trimmedUrl = repoObject.RepoUrl[(repoObject.RepoUrl.IndexOf("//") + 2)..(repoObject.RepoUrl.Length)];
                trimmedUrl = trimmedUrl[(trimmedUrl.IndexOf('/') + 1)..(trimmedUrl.Length)];
                string owner = trimmedUrl[0..trimmedUrl.IndexOf('/', 1)];
                string designation = trimmedUrl[(owner.Length + 1)..trimmedUrl.Length];
                if (designation.Contains('/')) {
                    designation = designation[0..trimmedUrl.IndexOf('/', owner.Length + 1)];
                }

                ExecuteMySqlCommand($"" +
                    $"INSERT INTO cve.repositories (guid, repoUrl, repoOwner, repoDesignation, tag) " +
                    $"VALUES (" +
                    $"'{repoId}'," +
                    $"'{repoObject.RepoUrl}'," +
                    $"'{owner}'," +
                    $"'{designation}'," +
                    $"'{repoObject.RepoTag ?? ""}');");

                await Clone(repoObject.RepoUrl, repoObject.RepoTag ?? "", repoId.ToString());

                return Ok(repoId);
            }
        }

        /// <summary></summary>
        /// <returns></returns>
        [HttpPost]
        [Route("pullCveAndConvert")]
        public IActionResult PullAndConvertCveFiles() {
            try {
                ProcessStartInfo process = new ProcessStartInfo {
                    FileName = "bash",
                    RedirectStandardInput = true,
                    WorkingDirectory = $"",
                };

                Process runProcess = Process.Start(process)!;
                runProcess.StandardInput.WriteLine($"git " +
                    $"clone {CM.AppSettings["StandardCveUrlPlusTag"]!} " +  // git url
                    $"--branch cve_2023-12-31_at_end_of_day " +             // tag
                    $"raw");                                                // target dir
                runProcess.StandardInput.WriteLine($"exit");
                runProcess.WaitForExit();

                #region
                using (Operation.Time("ConvertRawCveToDb")) {
                    List<string> fileList = new List<string>();
                    List<int> indexToDelete = new List<int>();
                    string path = "raw";
                    ExploreFolder(path, fileList);

                    //filter for json files
                    foreach (int i in Enumerable.Range(0, fileList.Count)) {
                        if (!Regex.IsMatch(fileList[i], @"CVE-[-\S]+.json")) {
                            indexToDelete.Add(i);
                        }
                    }
                    foreach (int i in Enumerable.Range(0, indexToDelete.Count)) {
                        fileList.RemoveAt(indexToDelete[i] - i);
                    }

                    try {
                        // MySql Connection
                        MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);

                        // Create the Table cve.cve if it is not already there.
                        MySqlCommand cmdTable = new MySqlCommand("" +
                            "CREATE TABLE IF NOT EXISTS cve.cve(" +
                            "cve_number VARCHAR(20) PRIMARY KEY NOT NULL," +
                            "designation VARCHAR(500) NOT NULL," +
                            "version_affected TEXT NOT NULL," +
                            "full_text MEDIUMTEXT NOT NULL" +
                            ")", connection);
                        connection.Open();
                        cmdTable.ExecuteNonQuery();
                        connection.Close();

                        int insertIndex = 0;
                        foreach (string x in fileList) {
                            string insertIntoString = "INSERT INTO cve(cve_number, designation, version_affected, full_text) VALUES(@cve, @des, @ver, @ful)";
                            MySqlCommand cmdInsert = new MySqlCommand(insertIntoString, connection);

                            string json = System.IO.File.ReadAllText(x);
                            CVEcomp cve = JsonConvert.DeserializeObject<CVEcomp>(json)!;

                            string affected = "";
                            foreach (Affected y in cve.containers.cna.affected) {
                                foreach (Modells.Version z in y.versions) {
                                    affected += z.version + $"({z.status}) |";
                                }
                            }
                            if (affected.Length > 25_000) {
                                affected = "to long -> view full_text";
                            }
                            string product = "n/a";
                            try {
                                product = cve.containers.cna.affected[0].product;
                                if (product.Length > 500) {
                                    product = product[0..500];
                                }
                            }
                            catch {
                                product = "n/a";
                            }
                            cmdInsert.Parameters.AddWithValue("@cve", cve.cveMetadata.cveId);
                            cmdInsert.Parameters.AddWithValue("@des", product);
                            cmdInsert.Parameters.AddWithValue("@ver", affected);
                            cmdInsert.Parameters.AddWithValue("@ful", JsonConvert.SerializeObject(cve, Formatting.None));

                            connection.Open();
                            insertIndex += cmdInsert.ExecuteNonQuery();
                            connection.Close();
                        }

                        connection.Open();
                        MySqlCommand cmdIndexCreated = new MySqlCommand("CREATE INDEX idx_designation ON cve (designation);", connection);
                        cmdIndexCreated.ExecuteNonQuery();
                        connection.Close();

                        return Ok(insertIndex);
                    }
                    catch (Exception ex) {
                        return BadRequest(ex.StackTrace + "\n\n" + ex.Message);
                    }
                }
                #endregion
            }
            catch (Exception ex) {
                return BadRequest(ex.Message);
            }
        }
        #endregion

        #region Internal function(s)
        /// <summary>
        /// Adds file names of all files of a folder and its subfolders to a list
        /// </summary>
        /// <param name="folderPath">path to target folder</param>
        /// <param name="fileList">list of files</param>
        private static void ExploreFolder(string folderPath, List<string> fileList) {
            try {
                fileList.AddRange(Directory.GetFiles(folderPath));

                foreach (string subfolder in Directory.GetDirectories(folderPath)) {
                    ExploreFolder(subfolder, fileList);
                }
            }
            catch (Exception ex) {
                Console.WriteLine($"{ex.Message}");
            }
        }

        /// <summary>Search package in raw-json data</summary>
        /// <param name="packageName">Name of package to search</param>
        /// <returns>List of CveResults</returns>
        private List<CveResult> SearchInJson(string packageName) {
            List<string> fileList = new List<string>();
            List<int> indexToDelete = new List<int>();
            string path = $"{AppDomain.CurrentDomain.BaseDirectory}raw";
            ExploreFolder(path, fileList);

            foreach (int i in Enumerable.Range(0, fileList.Count)) {
                if (!Regex.IsMatch(fileList[i], @"CVE-[-\S]+.json")) {
                    indexToDelete.Add(i);
                }
            }
            foreach (int i in Enumerable.Range(0, indexToDelete.Count)) {
                fileList.RemoveAt(indexToDelete[i] - i);
            }
            // search in the files
            List<CveResult> results = [];
            using (Operation.Time($"Package \"{packageName}\"")) {
                int start = 0;
                foreach (int i in Enumerable.Range(start, fileList.Count - start)) {
                    CVEcomp item = JsonConvert.DeserializeObject<CVEcomp>(System.IO.File.ReadAllText(fileList[i]))!;
                    if (i % 100 == 0) {
                        Console.WriteLine(fileList[i] + " - " + i);
                    }
                    if (item.containers.cna.affected is null || item.containers.cna.affected.Any(x => x.product is null)) {
                        continue;
                    }
                    if (item.containers.cna.affected.Any(y => y.product.Equals(packageName))) {
                        foreach (int j in Enumerable.Range(0, item.containers.cna.affected.Count)) {
                            foreach (Modells.Version version in item.containers.cna.affected[j].versions) {
                                results.Add(new CveResult() {
                                    CveNumber = item.cveMetadata.cveId,
                                    Version = version.version,
                                });
                            }
                        }
                    }
                }
            }
            return results;
        }

        /// <summary>
        /// Clone a git repository.
        /// </summary>
        /// <param name="url">URL of git project to clone.</param>
        /// <param name="tag">Tag of git project.</param>
        /// <param name="dir">Directory where to clone project into.</param>
        /// <returns></returns>
        private static async Task Clone(string url, string tag, string dir) {
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
                            Process.Start("git", $"clone {url} --branch {tag} {AppDomain.CurrentDomain.BaseDirectory}{dir}");
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
        #endregion
    }
}
