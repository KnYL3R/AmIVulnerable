﻿//using Microsoft.AspNetCore.Mvc;
//using Modells;
//using Modells.Packages;
//using MySql.Data.MySqlClient;
//using Newtonsoft.Json;
//using SerilogTimings;
//using System.Data;
//using System.Diagnostics;
//using System.Text.Json;
//using F = System.IO.File;

//namespace AmIVulnerable.Controllers {

//    //[Route("api/[controller]")]
//    //[ApiController]

//    public class DependeciesController : ControllerBase {

//        #region Config
//        private readonly IConfiguration Configuration;

//        public DependeciesController(IConfiguration configuration) {
//            Configuration = configuration;
//        }
//        #endregion

//        /// <summary>
//        /// Extract dependecies of different project types as json
//        /// </summary>
//        /// <param name="projectType">Type of project to extract dependencies from</param>
//        /// <returns>OK if known project type. BadRequest if unknown project type.</returns>
//        //[HttpPost]
//        //[Route("extractTree")]
//        public IActionResult ExtractDependencies([FromQuery] ProjectType projectType,
//                                                    [FromQuery] Guid projectGuid) {
//            if (!(this.Request.Headers.Accept.Equals("application/json") || this.Request.Headers.Accept.Equals("*/*"))) {
//                return StatusCode(406);
//            }
//            if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + projectGuid.ToString())) {
//                return BadRequest("ProjectGuid does not exist.");
//            }
//            switch (projectType) {
//                case ProjectType.NodeJs: {
//                        ExecuteCommand("npm", "install", projectGuid.ToString());
//                        ExecuteCommand("rm", "tree.json", projectGuid.ToString());
//                        ExecuteCommand("npm", "list --all --json >> tree.json", projectGuid.ToString());
//                        List<Package> resTree = ExtractTree(AppDomain.CurrentDomain.BaseDirectory + projectGuid.ToString() + "/tree.json");
//                        F.WriteAllText(AppDomain.CurrentDomain.BaseDirectory + projectGuid.ToString() + "/depTree.json", JsonConvert.SerializeObject(resTree));

//                        JsonLdObject resultAsJsonLd = new JsonLdObject() {
//                            Context = "https://localhost:7203/views/nodePackageResult",
//                            Data = resTree
//                        };
//                        return Ok(resultAsJsonLd);
//                    }
//                default: {
//                        return BadRequest();
//                    }
//            }
//        }

//        /// <summary>
//        /// Extract dependecies of different project types as json and extract resulting dependency trees of vulnerabilities
//        /// </summary>
//        /// <param name="projectType">Type of project to extract dependencies from</param>
//        /// <returns>OK if vulnerability found. 299 if no vulnerability found. BadRequest if unknown project type is searched.</returns>
//        //[HttpPost]
//        //[Route("extractAndAnalyzeTree")]
//        public async Task<IActionResult> ExtractAndAnalyzeTreeAsync([FromQuery] ProjectType projectType,
//                                                                        [FromQuery] Guid projectGuid) {
//            if (!(this.Request.Headers.Accept.Equals("application/json") || this.Request.Headers.Accept.Equals("*/*"))) {
//                return StatusCode(406);
//            }
//            using (Operation.Time($"ExtractAndAnalyzeTreeAsync called with procjectType {projectType}")) {
//                if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + projectGuid.ToString())) {
//                    return BadRequest("ProjectGuid does not exist.");
//                }
//                switch (projectType) {
//                    case ProjectType.NodeJs: {
//                            ExecuteCommand("npm", "install", projectGuid.ToString());
//                            ExecuteCommand("rm", "tree.json", projectGuid.ToString());
//                            ExecuteCommand("npm", "list --all --json >> tree.json", projectGuid.ToString());
//                            List<Package> depTree = ExtractTree(AppDomain.CurrentDomain.BaseDirectory + projectGuid.ToString() + "/tree.json");
//                            List<PackageResult> resTree = await AnalyzeTreeAsync(depTree) ?? [];
//                            if (resTree.Count != 0) {
//                                JsonLdObject resultAsJsonLd = new JsonLdObject() {
//                                    Context = "https://localhost:7203/views/nodePackageResult",
//                                    Data = resTree
//                                };
//                                return Ok(resultAsJsonLd);
//                            }
//                            else {
//                                return StatusCode(299, "Keine Schwachstelle gefunden.");
//                            }
//                        }
//                    default: {
//                            return BadRequest();
//                        }
//                }
//            }
//        }

//        /// <summary>
//        /// Starts a process that runs a command.
//        /// </summary>
//        /// <param name="prog">Programm used for commands</param>
//        /// <param name="command">Command used for programm</param>
//        private void ExecuteCommand(string prog, string command, string dir) {
//            ProcessStartInfo process = new ProcessStartInfo {
//                FileName = "cmd",
//                RedirectStandardInput = true,
//                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory + dir,
//            };
//            Process runProcess = Process.Start(process)!;
//            runProcess.StandardInput.WriteLine($"{prog} {command}");
//            runProcess.StandardInput.WriteLine($"exit");
//            runProcess.WaitForExit();
//        }

//        /// <summary>
//        /// Extracts a tree from node project
//        /// </summary>
//        /// <param name="filePath">File path to rawAnalyze/tree.json</param>
//        /// <returns>List of vulnerable packages.</returns>
//        private List<Package> ExtractTree(string filePath) {
//            List<Package> packages = [];
//            using (JsonDocument jsonDocument = JsonDocument.Parse(F.ReadAllText(filePath))) {
//                if (jsonDocument.RootElement.TryGetProperty("dependencies", out JsonElement dependenciesElement) &&
//                    dependenciesElement.ValueKind == JsonValueKind.Object) {
//                    foreach (JsonProperty dependency in dependenciesElement.EnumerateObject()) {
//                        Package nodePackage = ExtractDependencyInfo(dependency);

//                        packages.Add(nodePackage);
//                    }
//                }
//            }
//            return packages;
//        }

//        /// <summary>
//        /// Extracts dependencies of a single dependency.
//        /// </summary>
//        /// <param name="dependency">Dependency that is searched for sundependencies and versions.</param>
//        /// <returns>NodePackage with all found dependencies and versions.</returns>
//        private Package ExtractDependencyInfo(JsonProperty dependency) {
//            Package nodePackage = new Package {
//                Name = dependency.Name
//            };
//            if (dependency.Value.TryGetProperty("version", out JsonElement versionElement) &&
//                versionElement.ValueKind == JsonValueKind.String) {
//                nodePackage.Version = versionElement.GetString() ?? "";
//            }
//            if (dependency.Value.TryGetProperty("dependencies", out JsonElement subDependenciesElement) &&
//                subDependenciesElement.ValueKind == JsonValueKind.Object) {
//                foreach (JsonProperty subDependency in subDependenciesElement.EnumerateObject()) {
//                    Package subNodePackage = ExtractDependencyInfo(subDependency);
//                    nodePackage.Dependencies.Add(subNodePackage);
//                }
//            }

//            return nodePackage;
//        }

//        /// <summary>
//        /// Analyse list of node packages, compare dependencies of each with cve and return list of NodePackageResult
//        /// </summary>
//        /// <param name="depTree">List of all top level node packages.</param>
//        /// <returns>List of NodePackageResult.</returns>
//        private async Task<List<PackageResult?>> AnalyzeTreeAsync(List<Package> depTree) {
//            List<Tuple<string, string>> nodePackages = [];
//            // preperation list
//            foreach (Package x in depTree) {
//                List<Package> y = AnalyzeSubtree(x);
//                foreach (Package z in y) {
//                    Tuple<string, string> tuple = new Tuple<string, string>(z.Name, z.Version);
//                    if (!nodePackages.Contains(tuple)) {
//                        nodePackages.Add(tuple);
//                    }
//                }
//            }

//            // analyze list
//            List<CveResult> cveResults = [];
//            foreach (Tuple<string, string> x in nodePackages) {
//                DataTable dtResult = SearchInMySql(x.Item1);
//                // convert the result
//                foreach (DataRow y in dtResult.Rows) {
//                    CveResult z = new CveResult() {
//                        CveNumber = y["cve_number"].ToString() ?? "",
//                        Designation = y["designation"].ToString() ?? "",
//                        Version = y["version_affected"].ToString() ?? ""
//                    };
//                    CVEcomp temp = JsonConvert.DeserializeObject<CVEcomp>(y["full_text"].ToString() ?? string.Empty) ?? new CVEcomp();
//                    try {
//                        if (temp.containers.cna.metrics.Count != 0) {
//                            z.CvssV31 = temp.containers.cna.metrics[0].cvssV3_1;
//                        }
//                        if (temp.containers.cna.descriptions.Count != 0) {
//                            z.Description = temp.containers.cna.descriptions[0];
//                        }
//                    }
//                    finally {
//                        cveResults.Add(z);
//                    }
//                }
//            }

//            // find the critical points
//            if (cveResults.Count == 0) {
//                return null;
//            }
//            List<PackageResult?> resulstList = [];
//            foreach (Package x in depTree) {
//                PackageResult? temp = CheckVulnerabilities(x, cveResults);
//                if (temp is not null) {
//                    resulstList.Add(temp);
//                }
//            }
//            return resulstList;
//        }

//        /// <summary>
//        /// Searches for all node package dependencies of a single node package.
//        /// </summary>
//        /// <param name="nodePackage">Node package to search</param>
//        /// <returns>List of all node package dependencies of a single node package.</returns>
//        private List<Package> AnalyzeSubtree(Package nodePackage) {
//            List<Package> res = [];
//            foreach (Package x in nodePackage.Dependencies) {
//                res.AddRange(AnalyzeSubtree(x));
//            }
//            res.Add(nodePackage);
//            return res;
//        }

//        /// <summary>
//        /// Compares node package dependencies with cve data.
//        /// </summary>
//        /// <param name="package">Package to search for cve tracked dependencies.</param>
//        /// <param name="cveData">List of CveResult data.</param>
//        /// <returns>NodePackageResult with all dependencies and status if it is a cve tracked dependency.</returns>
//        private PackageResult? CheckVulnerabilities(Package package, List<CveResult> cveData) {
//            PackageResult r = new PackageResult() {
//                Name = "",
//                isCveTracked = false
//            };
//            foreach (Package x in package.Dependencies) {
//                PackageResult? temp = CheckVulnerabilities(x, cveData);
//                if (temp is not null) {
//                    r.Dependencies.Add(temp);
//                }
//            }
//            foreach (CveResult x in cveData) { // check
//                if (x.Designation.Equals(package.Name)) {
//                    r.isCveTracked = true;
//                    r.CvssV31 = x.CvssV31;
//                    r.Description = x.Description;
//                }
//            }
//            if (r.isCveTracked == false && !DepCheck(r)) {
//                return null;
//            }
//            r.Name = package.Name;
//            r.Version = package.Version;
//            return r;
//        }

//        /// <summary>
//        /// If Package is cve tracked, return true. Check all dependencies recursively.
//        /// </summary>
//        /// <param name="package"></param>
//        /// <returns>True if any dependency is tracked. False if no dependencies are tracked.</returns>
//        private bool DepCheck(PackageResult package) {
//            foreach (PackageResult x in package.Dependencies) {
//                bool isTracked = DepCheck(x);
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

//        private DataTable SearchInMySql(string packageName) {
//            // MySql Connection
//            MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);

//            MySqlCommand cmd = new MySqlCommand($"" +
//                $"SELECT cve_number, designation, version_affected, full_text " +
//                $"FROM cve.cve " +
//                $"WHERE designation='{packageName}';", connection);

//            DataTable dataTable = new DataTable();
//            using (Operation.Time($"Query-Time for Package \"{packageName}\"")) {
//                // read the result
//                connection.Open();
//                MySqlDataReader reader = cmd.ExecuteReader();
//                dataTable.Load(reader);
//                connection.Close();
//            }
//            return dataTable;
//        }
//    }
//}
