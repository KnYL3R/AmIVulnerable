using System;
using System.Diagnostics;
using System.Text.Json;
using Modells.Packages;
using F = System.IO.File;

namespace Modells {
    public class Project {
        public string ProjectUrl { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = [];
        public List<Package> Packages { get; set; } = [];

        public string DirGuid { get; set; } = "";
        private readonly static string CLI = "cmd";
        private readonly string CLI_RM = CLI == "cmd" ? "del" : "rm";

        public Project(string projectUrl, List<string> tags) {
            ProjectUrl = projectUrl;
            Tags = tags;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="dirGuid"></param>
        /// <returns></returns>
        public async void MakeDependencyTreeAsync() {
            List<Package> dependencyTree = new List<Package>();
            //DirGuid = await Clone();
            DirGuid = "eeb6f385-e135-4fc3-9671-42ab9735e398";
            //Install();
            string treeJsonPath = MakeTree(DirGuid);
            Packages = ExtractTree(treeJsonPath);
        }

        private async Task<string> Clone() {
            if (ProjectUrl is null) {
                this.DirGuid = "Err";
                return "Err";
            }

            else { // clone the repo
                DirGuid = Guid.NewGuid().ToString();
                try {
                    ExecuteCommand("git", $"clone {ProjectUrl} {DirGuid}", "");
                }
                catch (Exception ex) {
                    await Console.Out.WriteLineAsync(ex.StackTrace);
                }
                return DirGuid;
            }
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
        private void Install() {
            ExecuteCommand(CLI_RM, ".npmrc", DirGuid);
            ExecuteCommand("npm", "install", DirGuid);
            ExecuteCommand("npm", "i --lockfile-version 3 --package-lock-only", DirGuid);
            return;
        }

        /// <summary>
        /// Starts a process that runs a command.
        /// </summary>
        /// <param name="prog">Programm used for commands</param>
        /// <param name="command">Command used for programm</param>
        private void ExecuteCommand(string prog, string command, string dir) {
            ProcessStartInfo process = new ProcessStartInfo {
                FileName = CLI,
                RedirectStandardInput = true,
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory + dir,
            };
            Process runProcess = Process.Start(process)!;
            runProcess.StandardInput.WriteLine($"{prog} {command}");
            runProcess.StandardInput.WriteLine($"exit");
            runProcess.WaitForExit();
        }

        /// <summary>
        /// Make a tree.json file
        /// </summary>
        /// <param name="projectUrl"></param>
        /// <param name="Tag"></param>
        /// <returns>File path</returns>
        private string MakeTree(string dirGuid) {
            ExecuteCommand("npm", "install", dirGuid);
            ExecuteCommand(CLI_RM, "tree.json", dirGuid);
            ExecuteCommand("npm", "list --all --json >> tree.json", dirGuid);
            return AppDomain.CurrentDomain.BaseDirectory + dirGuid + "/tree.json";
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        private List<Package> ExtractTree(string filePath) {
            List<Package> packages = [];
            using (JsonDocument jsonDocument = JsonDocument.Parse(F.ReadAllText(filePath))) {
                if (jsonDocument.RootElement.TryGetProperty("dependencies", out JsonElement dependenciesElement) &&
                    dependenciesElement.ValueKind == JsonValueKind.Object) {
                    foreach (JsonProperty dependency in dependenciesElement.EnumerateObject()) {
                        Package nodePackage = ExtractDependencyInfo(dependency);

                        packages.Add(nodePackage);
                    }
                }
            }
            return packages;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dependency"></param>
        /// <returns></returns>
        private Package ExtractDependencyInfo(JsonProperty dependency) {
            Package nodePackage = new Package {
                Name = dependency.Name
            };
            if (dependency.Value.TryGetProperty("version", out JsonElement versionElement) &&
                versionElement.ValueKind == JsonValueKind.String) {
                nodePackage.Version = versionElement.GetString() ?? "";
            }
            if (dependency.Value.TryGetProperty("dependencies", out JsonElement subDependenciesElement) &&
                subDependenciesElement.ValueKind == JsonValueKind.Object) {
                foreach (JsonProperty subDependency in subDependenciesElement.EnumerateObject()) {
                    Package subNodePackage = ExtractDependencyInfo(subDependency);
                    nodePackage.Dependencies.Add(subNodePackage);
                }
            }

            return nodePackage;
        }
    }
}