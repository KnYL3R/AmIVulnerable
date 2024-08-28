//using Microsoft.AspNetCore.Mvc;
//using Modells;
//using Modells.Packages;
//using MySql.Data.MySqlClient;
//using Newtonsoft.Json;
//using SerilogTimings;
//using System.Data;
//using System.Diagnostics;
//using System.Text.Json;
//using F = System.IO.File;
//using MP = Modells.Project;

//namespace AmIVulnerable.Controllers {

//    [Route("api/oldReport")]
//    [ApiController]
//    public class ReportsController_ : ControllerBase {

//        #region Config

//        private readonly static string CLI = "bash";
//        private readonly string CLI_RM = CLI == "cmd" ? "del" : "rm";

//        private readonly IConfiguration Configuration;
//        public ReportsController_(IConfiguration configuration) {
//            Configuration = configuration;
//        }

//        #endregion

//        #region Controller

//        /// <summary>
//        /// Generate a SimpleReport for a list of Projects
//        /// </summary>
//        /// <param name="mavenList"></param>
//        /// <returns></returns>
//        [HttpPost]
//        [Route("simpleAnalyseNpmList")]
//        public async Task<IActionResult> SimpleAnalyseNpmList([FromBody] List<MP> npmList) {
//            List<SimpleReportLine> simpleReport = [];
//            foreach (MP npm in npmList) {
//                string dirGuid = await CloneProject(npm);
//                if (dirGuid.Equals("Err")) {
//                    return BadRequest("Could not clone project!");
//                }
//                foreach (string tag in npm.Tags) {
//                    // checkot HEAD
//                    // CheckoutTagProject(dirGuid); (Not needed due to always cloning newest commit)
//                    // Use DateTime.Now to use all CVE Data
//                    DateTime commitDateTimeC = GetCommitDateTime(dirGuid);
//                    List<PackageResult> depTreeCurrent = AnalyseTree(ExtractTree(MakeTree(dirGuid)), commitDateTimeC);
//                    // checkout release tag
//                    CheckoutTagProject(dirGuid, tag);
//                    DateTime commitDateTimeR = GetCommitDateTime(dirGuid);
//                    List<PackageResult> depTreeRelease = AnalyseTree(ExtractTree(MakeTree(dirGuid)), commitDateTimeR);
//                    //checkout latest commit again for new tag analysis (if done prematurely you end up in detached HEAD state!)
//                    CheckoutTagProject(dirGuid);

//                    simpleReport.Add(GenerateSimpleReportLine(depTreeRelease, depTreeCurrent, npm.ProjectUrl, tag, commitDateTimeR));
//                }
//                DeleteProject(dirGuid);
//            }
//            return Ok(simpleReport);
//        }

//        #endregion

//        #region Internal function(s)

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="npm"></param>
//        private async Task<string> CloneProject(MP npm) {
//            if (npm.ProjectUrl is null) {
//                return "Err";
//            }

//            else { // clone the repo
//                Guid repoId = Guid.NewGuid();
//                string trimmedUrl = npm.ProjectUrl[(npm.ProjectUrl.IndexOf("//") + 2)..(npm.ProjectUrl.Length)];
//                trimmedUrl = trimmedUrl[(trimmedUrl.IndexOf('/') + 1)..(trimmedUrl.Length)];
//                string owner = trimmedUrl[0..trimmedUrl.IndexOf('/', 1)];
//                string designation = trimmedUrl[(owner.Length + 1)..trimmedUrl.Length];
//                if (designation.Contains('/')) {
//                    designation = designation[0..trimmedUrl.IndexOf('/', owner.Length + 1)];
//                }

//                ExecuteMySqlCommand($"" +
//                    $"INSERT INTO cve.repositories (guid, repoUrl, repoOwner, repoDesignation) " +
//                    $"VALUES (" +
//                    $"'{repoId}', " +
//                    $"'{npm.ProjectUrl}', " +
//                    $"'{owner}', " +
//                    $"'{designation}');");

//                await Clone(npm.ProjectUrl, repoId.ToString());
//                return repoId.ToString();
//            }
//        }

//        /// <summary>
//        /// Clone a git repository.
//        /// </summary>
//        /// <param name="url">URL of git project to clone.</param>
//        /// <param name="tag">Tag of git project.</param>
//        /// <param name="dir">Directory where to clone project into.</param>
//        /// <returns></returns>
//        private static async Task Clone(string url, string dir) {
//            try {
//                await Task.Run(() => {
//                    if (Directory.Exists(dir)) {
//                        RemoveReadOnlyAttribute(dir);
//                        Directory.Delete(dir, true);
//                    }
//                    Process.Start("git", $"clone {url} {AppDomain.CurrentDomain.BaseDirectory + dir}").WaitForExit();
//                });
//            }
//            catch (Exception ex) {
//                await Console.Out.WriteLineAsync(ex.StackTrace);
//            }
//        }

//        /// <summary>
//        /// Removes read only access of files.
//        /// </summary>
//        /// <param name="path">File path to folder where all read only attributes of files need to be removed.</param>
//        private static void RemoveReadOnlyAttribute(string path) {
//            DirectoryInfo directoryInfo = new DirectoryInfo(path);

//            foreach (FileInfo file in directoryInfo.GetFiles()) {
//                file.Attributes &= ~FileAttributes.ReadOnly;
//            }

//            foreach (DirectoryInfo subDirectory in directoryInfo.GetDirectories()) {
//                RemoveReadOnlyAttribute(subDirectory.FullName);
//            }
//        }

//        private DataTable ExecuteMySqlCommand(string command) {
//            // MySql Connection
//            MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);
//            MySqlCommand cmd = new MySqlCommand(command, connection);
//            DataTable dataTable = new DataTable();
//            connection.Open();

//            MySqlDataReader reader = cmd.ExecuteReader();
//            dataTable.Load(reader);
//            connection.Close();
//            return dataTable;
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="tag"></param>
//        private bool CheckoutTagProject(string dir, string tag = "-") {
//            try {
//                ProcessStartInfo process = new ProcessStartInfo {
//                    FileName = CLI,
//                    RedirectStandardInput = true,
//                    WorkingDirectory = $"{AppDomain.CurrentDomain.BaseDirectory + dir}",
//                };

//                Process runProcess = Process.Start(process)!;
//                runProcess.StandardInput.WriteLine($"git " + "stash");
//                runProcess.StandardInput.WriteLine($"git " + $"checkout {tag}");
//                runProcess.StandardInput.WriteLine($"exit");
//                runProcess.WaitForExit();

//                return true;
//            }
//            catch (Exception ex) {
//                Console.WriteLine("Error with clone, tag?\n" + ex.Message);
//                return false;
//            }
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="dir"></param>
//        private void DeleteProject(string dir) {
//            if (Directory.Exists(dir)) {
//                RemoveReadOnlyAttribute(dir);
//                Directory.Delete(dir, true);

//                //dir is guid (folder named after guid)
//                ExecuteMySqlCommand($"DELETE FROM cve.repositories WHERE guid LIKE '{dir}';");
//            }
//        }

//        #region MakeTree

//        /// <summary>
//        /// Make a tree.json file
//        /// </summary>
//        /// <param name="projectUrl"></param>
//        /// <param name="Tag"></param>
//        /// <returns>File path</returns>
//        private string MakeTree(string dirGuid) {
//            ExecuteCommand("npm", "install", dirGuid);
//            ExecuteCommand(CLI_RM, "tree.json", dirGuid);
//            ExecuteCommand("npm", "list --all --json >> tree.json", dirGuid);
//            return dirGuid + "/tree.json";
//        }

//        #endregion

//        #region ExtractTree

//        /// <summary>
//        /// Extract internal representation of tree from tree.json
//        /// </summary>
//        /// <param name="treeFilePath"></param>
//        /// <returns></returns>
//        private List<Package> ExtractTree(string treeFilePath) {
//            List<Package> packageList = [];
//            using (JsonDocument jsonDocument = JsonDocument.Parse(F.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + treeFilePath))) {
//                if (jsonDocument.RootElement.TryGetProperty("dependencies", out JsonElement dependenciesElement) &&
//                    dependenciesElement.ValueKind == JsonValueKind.Object) {
//                    foreach (JsonProperty dependency in dependenciesElement.EnumerateObject()) {
//                        Package package = ExtractDependencyInfo(dependency);

//                        packageList.Add(package);
//                    }
//                }
//            }
//            return packageList;
//        }

//        /// <summary>
//        /// Extracts dependencies of a single dependency.
//        /// </summary>
//        /// <param name="dependency">Dependency that is searched for sundependencies and versions.</param>
//        /// <returns>NodePackage with all found dependencies and versions.</returns>
//        private Package ExtractDependencyInfo(JsonProperty dependency) {
//            Package package = new Package {
//                Name = dependency.Name
//            };
//            if (dependency.Value.TryGetProperty("version", out JsonElement versionElement) &&
//                versionElement.ValueKind == JsonValueKind.String) {
//                package.Version = versionElement.GetString() ?? "";
//            }
//            if (dependency.Value.TryGetProperty("dependencies", out JsonElement subDependenciesElement) &&
//                subDependenciesElement.ValueKind == JsonValueKind.Object) {
//                foreach (JsonProperty subDependency in subDependenciesElement.EnumerateObject()) {
//                    Package subPackage = ExtractDependencyInfo(subDependency);
//                    package.Dependencies.Add(subPackage);
//                }
//            }
//            return package;
//        }

//        #endregion

//        #region AnalyseTree

//        private record PackageRecord(string designation, string version);

//        /// <summary>
//        /// Check Package list agains cve data, differentiate between current cve database and past versions through cveVersion
//        /// </summary>
//        /// <param name="packageList"></param>
//        /// <param name="commitTime"></param>
//        /// <returns></returns>
//        private List<PackageResult> AnalyseTree(List<Package> packages, DateTime commitTime) {
//            List<PackageRecord> uniquePackageRecords = [];
//            foreach (Package package in packages) {
//                List<Package> subPackages = ListSubTreePackages(package);
//                foreach (Package subPackage in subPackages) {
//                    PackageRecord packageRecord = new PackageRecord(subPackage.Name, subPackage.Version);
//                    if(!uniquePackageRecords.Contains(packageRecord)) {
//                        uniquePackageRecords.Add(packageRecord);
//                    }
//                }
//            }
//            List<CveResult> cveResults = [];
//            foreach (PackageRecord packageRecord in uniquePackageRecords) {
//                DataTable dataTableResults = SearchInMySql(packageRecord.designation, commitTime);
//                // dataTableResult to CveResult
//                foreach (DataRow dataTableResult in dataTableResults.Rows) {
//                    if(!HasPublishDateTimeBeforeCommitDateTime(dataTableResult, commitTime)) {
//                        continue;
//                    }
//                    CveResult cveResult = new CveResult() {
//                        CveNumber = dataTableResult["cve_number"].ToString() ?? "",
//                        Designation = dataTableResult["designation"].ToString() ?? "",
//                        Version = dataTableResult["version_affected"].ToString() ?? ""
//                    };

//                    CVEcomp cVEcomp = JsonConvert.DeserializeObject<CVEcomp>(dataTableResult["full_text"].ToString() ?? string.Empty) ?? new CVEcomp();
//                    try {
//                        if (cVEcomp.containers.cna.metrics.Count != 0) {
//                            cveResult.CvssV31 = cVEcomp.containers.cna.metrics[0].cvssV3_1;
//                        }
//                        if (cVEcomp.containers.cna.descriptions.Count != 0) {
//                            cveResult.Description = cVEcomp.containers.cna.descriptions[0];
//                        }
//                    }
//                    finally {
//                        cveResults.Add(cveResult);
//                    }
//                }
//            }

//            if (cveResults.Count == 0) {
//                return [];
//            }

//            List<PackageResult> packageResults = [];
//            foreach (Package package in packages) {
//                PackageResult? packageResult = CheckVulnerabilities(package, cveResults);
//                if(packageResult is not null) {
//                    packageResults.Add(packageResult);
//                }
//            }
//            return packageResults;
//        }

//        /// <summary>
//        /// Searches for all node package dependencies of a single node package.
//        /// </summary>
//        /// <param name="package">Package to search</param>
//        /// <returns>List of all node package dependencies of a single node package.</returns>
//        private List<Package> ListSubTreePackages(Package package) {
//            List<Package> resultList = [];
//            foreach (Package x in package.Dependencies) {
//                resultList.AddRange(ListSubTreePackages(x));
//            }
//            resultList.Add(package);
//            return resultList;
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="packageName"></param>
//        /// <returns></returns>
//        private DataTable SearchInMySql(string designation, DateTime commitTime) {

//            // MySql Connection
//            MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);

//            //TODO: Compare Version!
//            MySqlCommand mySqlCommand = new MySqlCommand($"" +
//                $"SELECT cve_number, designation, version_affected, full_text " +
//                $"FROM cve.cve " +
//                $"WHERE designation LIKE '%| {designation} |%';", connection);

//            //TODO: is Operation.TIme this still needed?
//            DataTable dataTable = new DataTable();
//            using (Operation.Time($"Query-Time for Package \"{designation}\"")) {
//                // read the result
//                connection.Open();
//                MySqlDataReader reader = mySqlCommand.ExecuteReader();
//                dataTable.Load(reader);
//                connection.Close();
//            }
//            return dataTable;
//        }

//        private bool HasPublishDateTimeBeforeCommitDateTime(DataRow row, DateTime commitDateTime) {
//            CVEcomp cVEcomp = JsonConvert.DeserializeObject<CVEcomp>(row["full_text"].ToString()!) ?? new CVEcomp();
//            try {
//                if(cVEcomp.containers.cna.datePublic < commitDateTime) {
//                    return true;
//                }
//                return false;
                
//            } catch {
//                return false;
//            }
//        }

//        private DateTime GetCommitDateTime(string guid) {
//            return GetTagDateTime(guid);
//        }


//        /// <summary>
//        /// Compares node package dependencies with cve data.
//        /// </summary>
//        /// <param name="package">Package to search for cve tracked dependencies.</param>
//        /// <param name="cveData">List of CveResult data.</param>
//        /// <returns>NodePackageResult with all dependencies and status if it is a cve tracked dependency.</returns>
//        private PackageResult? CheckVulnerabilities(Package package, List<CveResult> cveData) {
//            PackageResult packageResult = new PackageResult() {
//                Name = "",
//                isCveTracked = false
//            };
//            foreach (Package x in package.Dependencies) {
//                PackageResult? temp = CheckVulnerabilities(x, cveData);
//                if (temp is not null) {
//                    packageResult.Dependencies.Add(temp);
//                }
//            }
//            foreach (CveResult x in cveData) { // check
//                if (x.Designation.Equals(package.Name)) {
//                    packageResult.isCveTracked = true;
//                    packageResult.CvssV31 = x.CvssV31;
//                    packageResult.Description = x.Description;
//                }
//            }
//            if (packageResult.isCveTracked == false && !DepCheck(packageResult)) {
//                return null;
//            }
//            packageResult.Name = package.Name;
//            packageResult.Version = package.Version;
//            return packageResult;
//        }

//        /// <summary>
//        /// If Package is cve tracked, return true. Check all dependencies recursively.
//        /// </summary>
//        /// <param name="package"></param>
//        /// <returns>True if any dependency is tracked. False if no dependencies are tracked.</returns>
//        private bool DepCheck(PackageResult package) {
//            foreach (PackageResult packageResult in package.Dependencies) {
//                bool isTracked = DepCheck(packageResult);
//                if (isTracked) {
//                    goto isTrue;
//                }
//            }
//            if (package.isCveTracked) {
//                return true;
//            }
//            else {
//                return false;
//            }
//        isTrue:
//            return true;
//        }

//        #endregion

//        #region GenerateSimpleReportLine

//        private SimpleReportLine GenerateSimpleReportLine(List<PackageResult> releaseVulnerabilitiesList, List<PackageResult> currentVulnerabilitiesList, string projectUrl, string tag, DateTime commitDateTime) {
//            SimpleReportLine simpleReportLine = new SimpleReportLine();
//            // Tag and URL
//            simpleReportLine.ProjectUrl = projectUrl;
//            simpleReportLine.Tag = tag;
//            // Num of Dependencies
//            simpleReportLine.TotalReleaseDirectDependencies = releaseVulnerabilitiesList.Count;
//            simpleReportLine.TotalReleaseDirectAndTransitiveDependencies = CountDirectAndTransitiveDependencies(releaseVulnerabilitiesList);
//            simpleReportLine.TotalCurrentDirectDependencies = currentVulnerabilitiesList.Count;
//            simpleReportLine.TotalCurrentDirectAndTransitiveDependencies = CountDirectAndTransitiveDependencies(currentVulnerabilitiesList);
//            // Num of Vulnerabilities
//            simpleReportLine.TotalReleaseDirectVulnerabilities = CountDirectVulnerabilities(releaseVulnerabilitiesList);
//            simpleReportLine.TotalReleaseDirectAndTransitiveVulnerabilities = CountDirectAndTransitiveVulnerabilities(releaseVulnerabilitiesList);
//            simpleReportLine.TotalCurrentDirectVulnerabilities = CountDirectVulnerabilities(currentVulnerabilitiesList);
//            simpleReportLine.TotalCurrentDirectAndTransitiveVulnerabilities = CountDirectAndTransitiveVulnerabilities(currentVulnerabilitiesList);
//            // Other Metrics
//            simpleReportLine.releaseVulnerabilitiesDepth = GetTransitiveVulnerabilitiesDepth(releaseVulnerabilitiesList);
//            simpleReportLine.releaseHighestDirectScore = GetHighestDirectScore(releaseVulnerabilitiesList);
//            simpleReportLine.currentHighestDirectScore = GetHighestDirectScore(currentVulnerabilitiesList);
//            simpleReportLine.releaseHighestDirectSeverity = GetHighestDirectSeverity(releaseVulnerabilitiesList);
//            simpleReportLine.currentHighestDirectSeverity = GetHighestDirectSeverity(currentVulnerabilitiesList);
//            simpleReportLine.releaseHighestTransitiveScore = GetHighestTransitiveScore(releaseVulnerabilitiesList);
//            simpleReportLine.currentHighestTransitiveScore = GetHighestTransitiveScore(currentVulnerabilitiesList);
//            simpleReportLine.releaseDateTime = commitDateTime;
//            return simpleReportLine;
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="packageResults"></param>
//        /// <param name="count"></param>
//        /// <returns></returns>
//        private int CountDirectAndTransitiveDependencies(List<PackageResult> packageResults, int count = 0) {
//            foreach (PackageResult packageResult in packageResults) {
//                if(packageResult.Dependencies.Count > 0) {
//                    count += CountDirectAndTransitiveDependencies(packageResult.Dependencies);
//                }
//                count += 1;
//            }
//            return count;
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="packageResults"></param>
//        /// <returns></returns>
//        private int CountDirectVulnerabilities(List<PackageResult> packageResults) {
//            int count = 0;
//            foreach (PackageResult packageResult in packageResults) {
//                if (packageResult.isCveTracked) {
//                    count += 1;
//                }
//            }
//            return count;
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="packageResults"></param>
//        /// <param name="count"></param>
//        /// <returns></returns>
//        private int CountDirectAndTransitiveVulnerabilities(List<PackageResult> packageResults, int count = 0) {
//            foreach (PackageResult packageResult in packageResults) {
//                if (packageResult.Dependencies.Count > 0) {
//                    count += CountDirectAndTransitiveDependencies(packageResult.Dependencies);
//                }
//                if (packageResult.isCveTracked) {
//                    count += 1;
//                }
//            }
//            return count;
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="packageResults"></param>
//        /// <param name="depth"></param>
//        /// <returns></returns>
//        private List<int> GetTransitiveVulnerabilitiesDepth(List<PackageResult> packageResults, int depth = 0) {
//            List<int> partitionedDepthList= [];
//            foreach(PackageResult packageResult in packageResults) {
//                if (packageResult.isCveTracked) {
//                    partitionedDepthList.Add(depth);
//                }
//                if(packageResult.Dependencies is not null) {
//                    partitionedDepthList.AddRange(GetTransitiveVulnerabilitiesDepth(packageResult.Dependencies, depth + 1));
//                }
//            }
//            return partitionedDepthList;
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="packageResults"></param>
//        /// <returns></returns>
//        private double GetHighestDirectScore(List<PackageResult> packageResults) {
//            double highestScore = 0.0;
//            foreach (PackageResult packageResult in packageResults) {
//                if (packageResult.CvssV31 is not null && packageResult.CvssV31.baseScore != -1 && packageResult.CvssV31.baseScore > highestScore) {
//                    highestScore = packageResult.CvssV31.baseScore;
//                }
//            }
//            return highestScore;
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="packageResults"></param>
//        /// <returns></returns>
//        private string GetHighestDirectSeverity(List<PackageResult> packageResults) {
//            string highestSeverity = "";
//            foreach (PackageResult packageResult in packageResults) {
//                if (packageResult.CvssV31 is not null && packageResult.CvssV31.baseSeverity is not null && packageResult.CvssV31.baseSeverity != "HIGH") {
//                    return packageResult.CvssV31.baseSeverity;
//                }
//                if (packageResult.CvssV31 is not null && packageResult.CvssV31.baseSeverity == "MEDIUM" ) {
//                    highestSeverity = "MEDIUM";
//                    continue;
//                }
//                highestSeverity = packageResult.CvssV31.baseSeverity;
//            }
//            return highestSeverity;
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="packageResults"></param>
//        /// <param name="highestTransitiveScore"></param>
//        /// <returns></returns>
//        private double GetHighestTransitiveScore(List<PackageResult> packageResults, double highestTransitiveScore = 0.0) {
//            foreach (PackageResult packageResult in packageResults) {
//                if (packageResult.CvssV31 is not null && packageResult.CvssV31.baseScore != -1 && packageResult.CvssV31.baseScore > highestTransitiveScore) {
//                    highestTransitiveScore = packageResult.CvssV31.baseScore;
//                }
//                if (packageResult.Dependencies is not null) {
//                    highestTransitiveScore = GetHighestTransitiveScore(packageResult.Dependencies, highestTransitiveScore);
//                }
//            }
//            return highestTransitiveScore;
//        }

//        #endregion


//        /// <summary>
//        /// Starts a process that runs a command.
//        /// </summary>
//        /// <param name="prog">Programm used for commands</param>
//        /// <param name="command">Command used for programm</param>
//        private void ExecuteCommand(string prog, string command, string dir) {
//            ProcessStartInfo process = new ProcessStartInfo {
//                FileName = CLI,
//                RedirectStandardInput = true,
//                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory + dir,
//            };
//            Process runProcess = Process.Start(process)!;
//            runProcess.StandardInput.WriteLine($"{prog} {command}");
//            runProcess.StandardInput.WriteLine($"exit");
//            runProcess.WaitForExit();
//        }

//        /// <summary>
//        /// 
//        /// </summary>
//        /// <param name="dir"></param>
//        /// <returns></returns>
//        private DateTime GetTagDateTime(string dir) {
//            ProcessStartInfo process = new ProcessStartInfo {
//                FileName = CLI,
//                RedirectStandardInput = true,
//                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory + dir,
//                RedirectStandardOutput = true,
//                UseShellExecute = false,
//            };
//            Process runProcess = Process.Start(process)!;
//            runProcess.StandardInput.WriteLine($"git log -1 --date=format:\"%Y-%m-%dT%T\" --format=\"%ad\"");
//            runProcess.StandardInput.WriteLine($"exit");
//            runProcess.WaitForExit();

//            string stringTagDateTime = runProcess.StandardOutput.ReadToEnd();
//            if (CLI.Equals("cmd")) {
//                int length = "0000-00-00T00:00:00".Length;
//                int startIndex = stringTagDateTime.LastIndexOf("--format=\"%ad\"") + "--format=\"%ad\"".Length;
//                stringTagDateTime = stringTagDateTime[(startIndex + 2)..(startIndex + length + 2)];
//            }

//            return DateTime.Parse(stringTagDateTime);
//        }
//        #endregion
//    }

//}
