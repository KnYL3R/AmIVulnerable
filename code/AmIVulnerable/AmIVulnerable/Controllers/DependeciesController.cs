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

        private async Task<List<NodePackageResult>?> analyzeTreeAsync(List<NodePackage> depTree) {
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
            //List<CveResult> results = await searchDbController.SearchPackagesAsList(designation);
            List<CveResult> results = searchDbController.SearchPackagesAsListMono(designation.Take(10).ToList());
            // find the critical points
            if (results.Count == 0) {
                return null;
            }
            List<NodePackageResult> resulstList = [];
            foreach (NodePackage x in depTree) {
                List<Tuple<int, bool>> r = checkOnVulnerabilities([], x, results);
                if (r.Any(x => x.Item2.Equals(true))) {
                    resulstList.Add(addPackagePlusDependencyStatus(x, r));
                }
            }
            return resulstList;
        }

        private List<NodePackage> analyzeSubtree(NodePackage nodePackage) {
            List<NodePackage> res = [];
            foreach(NodePackage x in nodePackage.Dependencies) {
                res.AddRange(analyzeSubtree(x));
            }
            res.Add(nodePackage);
            return res;
        }

        private List<Tuple<int, bool>> checkOnVulnerabilities(List<Tuple<int, bool>> packageMatrix, NodePackage package, List<CveResult> cveList) {
            List<Tuple<int, bool>> matrix = [];
            matrix.AddRange(packageMatrix);
            foreach (NodePackage x in package.Dependencies) {
                matrix.AddRange(checkOnVulnerabilities(matrix, x, cveList));
            }
            // check if vulnerable
            foreach (CveResult cveResult in cveList) {
                // TODO:
            }
            return matrix;
        }

        private NodePackageResult addPackagePlusDependencyStatus(NodePackage x, List<Tuple<int, bool>> r) {
            NodePackageResult res = new NodePackageResult() {
                Name = x.Name,
                Version = x.Version,
                isCveTracked = r[0].Item2
            };
            r.RemoveAt(0);
            foreach (NodePackage y in x.Dependencies) {
                res.Dependencies.Add(addPackagePlusDependencyStatus(x, r));
            }
            return res;
        }
    }
}
