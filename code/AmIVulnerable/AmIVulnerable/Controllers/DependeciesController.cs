using LiteDbLib.Controller;
using Microsoft.AspNetCore.Mvc;
using Modells;
using Modells.Packages;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Text.Json;
using F = System.IO.File;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class DependeciesController : ControllerBase {

        /// <summary>
        /// Extract dependecies of different project types as json
        /// </summary>
        /// <param name="projectType">Type of project to extract dependencies from</param>
        /// <returns>OK if known project type. BadRequest if unknown project type.</returns>
        [HttpGet]
        [Route("ExtractTree")]
        public IActionResult ExtractDependencies([FromHeader] ProjectType projectType) {
            switch (projectType) {
                case ProjectType.NodeJs: {
                        ExecuteCommand("npm", "install");
                        ExecuteCommand("npm", "list --all --json >> tree.json");
                        List<NodePackage> resTree = ExtractTree(AppDomain.CurrentDomain.BaseDirectory + "rawAnalyze/tree.json");
                        F.WriteAllText(AppDomain.CurrentDomain.BaseDirectory + "rawAnalyze/depTree.json", JsonConvert.SerializeObject(resTree));
                        return Ok(JsonConvert.SerializeObject(resTree));
                    }
                default: {
                        return BadRequest();
                    }
            }
        }

        /// <summary>
        /// Extract dependecies of different project types as json and extract resulting dependency trees of vulnerabilities
        /// </summary>
        /// <param name="projectType">Type of project to extract dependencies from</param>
        /// <returns>OK if vulnerability found. 299 if no vulnerability found. BadRequest if unknown project type is searched.</returns>
        [HttpGet]
        [Route("ExtractAndAnalyzeTree")]
        public async Task<IActionResult> ExtractAndAnalyzeTreeAsync([FromHeader] ProjectType projectType) {
            switch (projectType) {
                case ProjectType.NodeJs: {
                        ExecuteCommand("npm", "install");
                        ExecuteCommand("del", "tree.json");
                        ExecuteCommand("npm", "list --all --json >> tree.json");
                        List<NodePackage> depTree = ExtractTree(AppDomain.CurrentDomain.BaseDirectory + "rawAnalyze/tree.json");
                        List<NodePackageResult> resTree = await analyzeTreeAsync(depTree) ?? [];
                        if (resTree.Count != 0) {
                            return Ok(JsonConvert.SerializeObject(resTree));
                        }
                        else {
                            return StatusCode(299, "Keine Schwachstelle gefunden.");
                        }
                    }
                default: {
                        return BadRequest();
                    }
            }
        }

        /// <summary>
        /// Starts a process that runs a command.
        /// </summary>
        /// <param name="prog">Programm used for commands</param>
        /// <param name="command">Command used for programm</param>
        private void ExecuteCommand(string prog, string command) {
            ProcessStartInfo process = new ProcessStartInfo {
                FileName = "cmd",
                RedirectStandardInput = true,
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory + "rawAnalyze",
            };
            Process runProcess = Process.Start(process)!;
            runProcess.StandardInput.WriteLine($"{prog} {command}");
            runProcess.StandardInput.WriteLine($"exit");
            runProcess.WaitForExit();
        }

        /// <summary>
        /// Extracts a tree from node project
        /// </summary>
        /// <param name="filePath">File path to rawAnalyze/tree.json</param>
        /// <returns>List of vulnerable packages.</returns>
        private List<NodePackage> ExtractTree(string filePath) {
            List<NodePackage> packages = [];
            using (JsonDocument jsonDocument = JsonDocument.Parse(F.ReadAllText(filePath))) {
                if (jsonDocument.RootElement.TryGetProperty("dependencies", out JsonElement dependenciesElement) &&
                    dependenciesElement.ValueKind == JsonValueKind.Object) {
                    foreach (JsonProperty dependency in dependenciesElement.EnumerateObject()) {
                        NodePackage nodePackage = ExtractDependencyInfo(dependency);

                        packages.Add(nodePackage);
                    }
                }
            }
            return packages;
        }

        /// <summary>
        /// Extracts dependencies of a single dependency.
        /// </summary>
        /// <param name="dependency">Dependency that is searched for sundependencies and versions.</param>
        /// <returns>NodePackage with all found dependencies and versions.</returns>
        private NodePackage ExtractDependencyInfo(JsonProperty dependency) {
            NodePackage nodePackage = new NodePackage {
                Name = dependency.Name
            };
            if (dependency.Value.TryGetProperty("version", out JsonElement versionElement) &&
                versionElement.ValueKind == JsonValueKind.String) {
                nodePackage.Version = versionElement.GetString() ?? "";
            }
            if (dependency.Value.TryGetProperty("dependencies", out JsonElement subDependenciesElement) &&
                subDependenciesElement.ValueKind == JsonValueKind.Object) {
                foreach (JsonProperty subDependency in subDependenciesElement.EnumerateObject()) {
                    NodePackage subNodePackage = ExtractDependencyInfo(subDependency);
                    nodePackage.Dependencies.Add(subNodePackage);
                }
            }

            return nodePackage;
        }

        /// <summary>
        /// ??
        /// </summary>
        /// <param name="depTree"></param>
        /// <returns></returns>
        private async Task<List<NodePackageResult?>?> analyzeTreeAsync(List<NodePackage> depTree) {
            List<Tuple<string, string>> nodePackages = [];
            // preperation list
            foreach (NodePackage x in depTree) {
                List<NodePackage> y = analyzeSubtree(x);
                foreach (NodePackage z in y) {
                    Tuple<string, string> tuple = new Tuple<string, string>(z.Name, z.Version);
                    if (!nodePackages.Contains(tuple)) {
                        nodePackages.Add(tuple);
                    }
                }
            }
            // analyze list
            SearchDbController searchDbController = new SearchDbController();
            List<string> designation = [];
            foreach (Tuple<string, string> x in nodePackages) {
                designation.Add(x.Item1);
            }

            List<CveResult> results = await searchDbController.SearchPackagesAsList(designation);
            //List<CveResult> results = searchDbController.SearchPackagesAsListMono(designation);

            // find the critical points
            if (results.Count == 0) {
                return null;
            }
            List<NodePackageResult?> resulstList = [];
            foreach (NodePackage x in depTree) {
                NodePackageResult? temp = checkVulnerabilities(x, results);
                if (temp is not null) {
                    resulstList.Add(temp);
                }
            }
            return resulstList ?? [];
        }

        /// <summary>
        /// Searches for all node package dependencies of a single node package.
        /// </summary>
        /// <param name="nodePackage">Node package to search</param>
        /// <returns>List of all node package dependencies of a single node package.</returns>
        private List<NodePackage> analyzeSubtree(NodePackage nodePackage) {
            List<NodePackage> res = [];
            foreach(NodePackage x in nodePackage.Dependencies) {
                res.AddRange(analyzeSubtree(x));
            }
            res.Add(nodePackage);
            return res;
        }

        /// <summary>
        /// Compares node package dependencies with cve data.
        /// </summary>
        /// <param name="package">Package to search for cve tracked dependencies.</param>
        /// <param name="cveData">List of CveResult data.</param>
        /// <returns>NodePackageResult with all dependencies and status if it is a cve tracked dependency.</returns>
        private NodePackageResult? checkVulnerabilities(NodePackage package, List<CveResult> cveData) {
            NodePackageResult r = new NodePackageResult() {
                Name = "",
                isCveTracked = false
            };
            foreach (NodePackage x in package.Dependencies) {
                NodePackageResult? temp = checkVulnerabilities(x, cveData);
                if (temp is not null) {
                    r.Dependencies.Add(temp);
                }
            }
            foreach (CveResult x in cveData) { // check
                if (x.Designation.Equals(package.Name)) {
                    r.isCveTracked = true;
                }
            }
            if (r.isCveTracked == false && !depCheck(r)) {
                return null;
            }
            r.Name = package.Name;
            r.Version = package.Version;
            return r;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="package"></param>
        /// <returns></returns>
        private bool depCheck(NodePackageResult package) {
            foreach (NodePackageResult x in package.Dependencies) {
                bool isTracked = depCheck(x);
                if (isTracked) {
                    goto isTrue; 
                }
            }
            if (package.isCveTracked) {
                return true;
            }
            else {
                return false;
            }
            isTrue:
            return true;
        }
    }
}
