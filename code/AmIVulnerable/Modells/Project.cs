using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using F = System.IO.File;
using Modells.Packages;

namespace Modells {
    public class Project {
        public string ProjectUrl { get; set; } = "";
        public List<Tag> Results { get; set; } = [];
        [JsonIgnore]
        public List<string> Tags { get; set; } = [];
        [JsonIgnore]
        public List<Package> Packages { get; set; } = [];

        [JsonIgnore]
        public string DirGuid { get; set; } = "";
        [JsonIgnore]
        public ProjectTypeEnum ProjectType { get; set; }
        private readonly static string CLI = "cmd";
        private readonly string CLI_RM = CLI == "cmd" ? "del" : "rm";

        public Project(string projectUrl) {
                ProjectUrl = projectUrl;
        }

        public class Tag {
            public string TagName { get; set; } = "";
            //List of either direct dependencies with vulnerabilities or vulnerabilities as root elements and their vulnerabilities
            public List<Rootdependency> RootDependencies { get; set; } = [];
        }

        public class Rootdependency {
            public string RootDependencyName { get; set; } = "";
            public List<Vulnerability> Vulnerabilities { get; set; } = [];
            public Rootdependency(string name, List<Vulnerability> vulnerabilities) {
                RootDependencyName = name;
                Vulnerabilities = vulnerabilities;
            }
        }

        public enum ProjectTypeEnum {
            Maven = 0,
            npm = 1,
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public async Task<string> MakeDependencyTreeCloneAsync() {
            List<Package> dependencyTree = new List<Package>();
            DirGuid = await Clone();
            if (F.Exists(AppDomain.CurrentDomain.BaseDirectory + DirGuid + "/package.json")) {
                ProjectType = ProjectTypeEnum.npm;
                Install();
            }
            // If is Maven Project
            if (F.Exists(AppDomain.CurrentDomain.BaseDirectory + DirGuid + "/pom.xml")) {
                ProjectType = ProjectTypeEnum.Maven;
            }


            string treeJsonPath = MakeTree(DirGuid);
            if(treeJsonPath == "NO_VALID_PROJECT") {
                return "FAILED";
            }
            Packages = ExtractTree(treeJsonPath);
            return "SUCCESS";
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public string MakeDependencyTreeCheckoutAsync(string tag) {
            List<Package> dependencyTree = new List<Package>();
            Checkout(tag);
            if(ProjectType == ProjectTypeEnum.npm) {
                Install();
            }
            string treeJsonPath = MakeTree(DirGuid);
            if (treeJsonPath == "NO_VALID_PROJECT") {
                return "FAILED";
            }
            Packages = ExtractTree(treeJsonPath);
            return "SUCCESS";
        }

        public bool Checkout (string tag) {
            try {
                ProcessStartInfo process = new ProcessStartInfo {
                    FileName = CLI,
                    RedirectStandardInput = true,
                    WorkingDirectory = $"{AppDomain.CurrentDomain.BaseDirectory + DirGuid}",
                };

                Process runProcess = Process.Start(process)!;
                runProcess.StandardInput.WriteLine($"git " + "reset --hard");
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

        public void SetTags() {
            ExecuteCommand("git", "tag > tags.txt", DirGuid);
            Tags = F.ReadAllLines(AppDomain.CurrentDomain.BaseDirectory + DirGuid + "/tags.txt").ToList();
            Tags.Reverse();
        }

        /// <summary>
        /// Deletes Project folder
        /// </summary>
        public void Delete() {
            RemoveReadOnlyAttribute(AppDomain.CurrentDomain.BaseDirectory + DirGuid);
            Directory.Delete(AppDomain.CurrentDomain.BaseDirectory + DirGuid, true);
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
            ExecuteCommand("git ", "status > status.txt", DirGuid);
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
            // If is npm project
            if(ProjectType == ProjectTypeEnum.npm) {
                ExecuteCommand(CLI_RM, "tree.json", dirGuid);
                ExecuteCommand("npm", "list --all --json > tree.json", dirGuid);
                return AppDomain.CurrentDomain.BaseDirectory + dirGuid + "/tree.json";
            } 
            // If is Maven Project
            if(ProjectType == ProjectTypeEnum.Maven) {
                ExecuteCommand(CLI_RM, "tree.json", dirGuid);
                ExecuteCommand("mvn", "org.apache.maven.plugins:maven-dependency-plugin:3.8.0:tree -DoutputFile=tree.json -DoutputType=json", dirGuid);
                return AppDomain.CurrentDomain.BaseDirectory + dirGuid + "/tree.json";
            }
            return "NO_VALID_PROJECT";
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        private List<Package> ExtractTree(string filePath) {
            List<Package> packages = [];
            using (JsonDocument jsonDocument = JsonDocument.Parse(F.ReadAllText(filePath))) {
                if(ProjectType == ProjectTypeEnum.npm) {
                    if (jsonDocument.RootElement.TryGetProperty("dependencies", out JsonElement dependenciesElement) &&
                        dependenciesElement.ValueKind == JsonValueKind.Object) {
                        foreach (JsonProperty dependency in dependenciesElement.EnumerateObject()) {
                            Package nodePackage = ExtractDependencyInfoFromProperty(dependency);

                            packages.Add(nodePackage);
                        }
                    }
                }
                if(ProjectType == ProjectTypeEnum.Maven) {
                    if (jsonDocument.RootElement.TryGetProperty("children", out JsonElement dependenciesElement) &&
                        dependenciesElement.ValueKind == JsonValueKind.Array) {
                        foreach (JsonElement dependency in dependenciesElement.EnumerateArray()) {
                            Package nodePackage = ExtractDependencyInfoFromElement(dependency);

                            packages.Add(nodePackage);
                        }
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
        private Package ExtractDependencyInfoFromProperty(JsonProperty dependencyProperty) {
            Package package = new Package();
            if(ProjectType == ProjectTypeEnum.npm) {
                package.Name = dependencyProperty!.Name;
                if (dependencyProperty!.Value.TryGetProperty("version", out JsonElement versionElement) &&
                    versionElement.ValueKind == JsonValueKind.String) {
                    package.Version = versionElement.GetString() ?? "";
                }
                if (dependencyProperty!.Value.TryGetProperty("dependencies", out JsonElement subDependenciesElement) &&
                    subDependenciesElement.ValueKind == JsonValueKind.Object) {
                    foreach (JsonProperty subDependency in subDependenciesElement.EnumerateObject()) {
                        Package subNodePackage = ExtractDependencyInfoFromProperty(subDependency);
                        package.Dependencies.Add(subNodePackage);
                    }
                }
            }
            return package;
        }

        private Package ExtractDependencyInfoFromElement(JsonElement dependencyElement) {
            Package package = new Package();
            if (ProjectType == ProjectTypeEnum.Maven) {
                package.Name = dependencyElement.GetProperty("groupId").ToString() + ":" + dependencyElement.GetProperty("artifactId").ToString();
                if (dependencyElement.TryGetProperty("version", out JsonElement version) && version.ValueKind == JsonValueKind.String) {
                    package.Version = version.ToString();
                }
                if (dependencyElement.TryGetProperty("children", out JsonElement childen) && childen.ValueKind == JsonValueKind.Array) {
                    foreach (JsonElement subDependency in childen.EnumerateArray()) {
                        Package subNodePackage = ExtractDependencyInfoFromElement(subDependency);
                        package.Dependencies.Add(subNodePackage);
                    }
                }
            }
            return package;
        }
    }
}