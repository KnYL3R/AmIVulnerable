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
    }
}
