using Microsoft.AspNetCore.Mvc;
using Modells;
using Modells.DTO;
using Modells.OsvResult;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Text.Json;
using F = System.IO.File;
using MP = Modells.Project;
using MPP = Modells.Packages.Package;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class ReportsController : ControllerBase {

        #region Config

        private readonly static string CLI = "cmd";
        private readonly string CLI_RM = CLI == "cmd" ? "del" : "rm";

        private readonly IConfiguration Configuration;
        public ReportsController(IConfiguration configuration) {
            Configuration = configuration;
        }

        #endregion

        #region Endpoints

        /// <summary>
        /// Generate TimeLine of project vulnerabilties
        /// </summary>
        /// <param name="projectsDto"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("vulnerabilityTimeLine")]
        public async Task<IActionResult> VulnerabilityTimeLine([FromBody] List<ProjectDto> projectsDto) {
            List<MP> projects = new List<MP>();
            foreach (ProjectDto projectDto in projectsDto) {
                projects.Add(new MP(projectDto.ProjectUrl));
            }
            List<TimeSlice> timeSeries = [];
            foreach (MP project in projects) {

                // Clone
                string cloneStatus = await project.MakeDependencyTreeCloneAsync();

                Console.WriteLine(cloneStatus);
                DateTime currentTagDateTime = GetTagDateTime(project.DirGuid);

                if(project.Packages.Count != 0) {
                    timeSeries.Add(MakeTimeSlice(project, currentTagDateTime, "release"));
                }

                project.SetTags();

                DateTime lastTagDateTime = currentTagDateTime.AddSeconds(-1);
                foreach (string tag in project.Tags) {

                    cloneStatus = project.MakeDependencyTreeCheckoutAsync(tag);
                    currentTagDateTime = GetTagDateTime(project.DirGuid);

                    if (project.Packages.Count != 0) {
                        timeSeries.Add(MakeTimeSlice(project, lastTagDateTime, tag));
                        timeSeries.Add(MakeTimeSlice(project, currentTagDateTime, tag));
                    }
                    lastTagDateTime = currentTagDateTime.AddSeconds(-1);
                    F.WriteAllText(AppDomain.CurrentDomain.BaseDirectory + "/reportCache.json", JsonConvert.SerializeObject(timeSeries));
                }
                //project.Delete(); //Comment out for Debugging
            }
            return Ok(timeSeries);
        }

        #endregion

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
        /// 
        /// </summary>
        /// <param name="dir"></param>
        /// <returns></returns>
        private DateTime GetTagDateTime(string dir) {
            ProcessStartInfo process = new ProcessStartInfo {
                FileName = CLI,
                RedirectStandardInput = true,
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory + dir,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            Process runProcess = Process.Start(process)!;
            runProcess.StandardInput.WriteLine($"git log -1 --date=format:\"%Y-%m-%dT%T\" --format=\"%ad\"");
            runProcess.StandardInput.WriteLine($"exit");
            runProcess.WaitForExit();

            string stringTagDateTime = runProcess.StandardOutput.ReadToEnd();
            if (CLI.Equals("cmd")) {
                int length = "0000-00-00T00:00:00".Length;
                int startIndex = stringTagDateTime.LastIndexOf("--format=\"%ad\"") + "--format=\"%ad\"".Length;
                stringTagDateTime = stringTagDateTime[(startIndex + 2)..(startIndex + length + 2)];
            }

            return DateTime.Parse(stringTagDateTime);
        }

        #region work functions

        private TimeSlice MakeTimeSlice(MP project, DateTime timestamp, string tagName = "master") {
            TimeSlice timeSlice = new TimeSlice();
            OsvResult osvResult = new OsvResult();
            osvResult = osvResult.OsvExtractVulnerabilities(project);
            
            timeSlice.TagName = tagName;
            timeSlice.Timestamp = timestamp;

            timeSlice.ProjectEcosystem = project.ProjectType;

            timeSlice.CountDirectDependencies = project.Packages.Count;

            // Count all Vulnerabilities found in osv scan
            int vulnerabilityCount = 0;
            if (osvResult.results.Count() != 0) {
                foreach (Packages osvPackage in osvResult.results[0].packages) {
                    vulnerabilityCount += osvPackage.vulnerabilities.Count;
                }
            }
            timeSlice.CountTotalFoundVulnerabilities = vulnerabilityCount;

            // Make list of all transitive dependencies
            List<MPP> allTransitiveDependencies = new List<MPP>();
            foreach (MPP package in project.Packages) {
                allTransitiveDependencies.AddRange(TransitiveDependencies(package.Dependencies));
            }
            timeSlice.CountTransitiveDependencies = allTransitiveDependencies.Count;

            timeSlice.CountUniqueTransitiveDependencies = GetUniquePackagesFromList(allTransitiveDependencies).Count;

            if(timeSlice.CountTotalFoundVulnerabilities > 0) {
                // Make list of direct vulnerabilities (Known and ToDate)
                List<MPP> allKnownDirectVulnerabilities = new List<MPP>();
                List<MPP> allToDateDirectVulnerabilities = new List<MPP>();
                foreach (MPP package in project.Packages) {
                    foreach (Packages vulnerablePackage in osvResult.results[0].packages) {
                        if (package.Name == vulnerablePackage.package.name && package.Version == vulnerablePackage.package.version) {
                            allToDateDirectVulnerabilities.Add(package);
                            if (timestamp >= OldestPublishedVulnerabilityDateTime(vulnerablePackage.vulnerabilities)) {
                                allKnownDirectVulnerabilities.Add(package);
                            }
                        }
                    }
                }
                timeSlice.CountKnownDirectVulnerableDependencies = allKnownDirectVulnerabilities.Count;
                timeSlice.CountToDateDirectVulnerableDependencies = allToDateDirectVulnerabilities.Count;
            } else {

                timeSlice.CountKnownDirectVulnerableDependencies = 0;
                timeSlice.CountToDateDirectVulnerableDependencies = 0;
            }

            if(timeSlice.CountTotalFoundVulnerabilities > 0) {
                // Use List of all transitive Packages from "CountTransitiveDependencies"
                List<MPP> allKnownTransitiveVulnerabilities = new List<MPP>();
                List<MPP> allToDateTransitiveVulnerabilities = new List<MPP>();
                foreach (Packages vulnerablePackage in osvResult.results[0].packages) {
                    foreach (MPP package in allTransitiveDependencies) {
                        if (package.Name == vulnerablePackage.package.name && package.Version == vulnerablePackage.package.version) {
                            allToDateTransitiveVulnerabilities.Add(package);
                            if (timestamp >= OldestPublishedVulnerabilityDateTime(vulnerablePackage.vulnerabilities)) {
                                allKnownTransitiveVulnerabilities.Add(package);
                            }
                        }
                    }
                }
                timeSlice.CountKnownTransitiveVulnerableDependencies = allKnownTransitiveVulnerabilities.Count;
                timeSlice.CountToDateTransitiveVulnerableDependencies = allToDateTransitiveVulnerabilities.Count;

                timeSlice.CountKnownUniqueTransitiveVulnerableDependencies = GetUniquePackagesFromList(allKnownTransitiveVulnerabilities).Count;
                timeSlice.CountToDateUniqueTransitiveVulnerableDependencies = GetUniquePackagesFromList(allToDateTransitiveVulnerabilities).Count;
            } else {
                timeSlice.CountKnownTransitiveVulnerableDependencies = 0;
                timeSlice.CountToDateTransitiveVulnerableDependencies = 0;
                timeSlice.CountKnownUniqueTransitiveVulnerableDependencies = 0;
                timeSlice.CountToDateUniqueTransitiveVulnerableDependencies = 0;
            }

            return timeSlice;
        }

        private MPP ExtractDependencyInfoNpm(JsonProperty dependency) {
            MPP package = new MPP {
                Name = dependency.Name
            };
            if (dependency.Value.TryGetProperty("version", out JsonElement versionElement) &&
                versionElement.ValueKind == JsonValueKind.String) {
                package.Version = versionElement.GetString() ?? "";
            }
            if (dependency.Value.TryGetProperty("dependencies", out JsonElement subDependenciesElement) &&
                subDependenciesElement.ValueKind == JsonValueKind.Object) {
                foreach (JsonProperty subDependency in subDependenciesElement.EnumerateObject()) {
                    MPP subPackage = ExtractDependencyInfoNpm(subDependency);
                    package.Dependencies.Add(subPackage);
                }
            }
            return package;
        }

        private List<MPP> TransitiveDependencies(List<MPP> packages) {
            if (!packages.Any()) {
                return [];
            }
            List<MPP> transitiveDependencies = new List<MPP>();

            foreach (MPP package in packages) {
                transitiveDependencies.Add(package);
                transitiveDependencies.AddRange(TransitiveDependencies(package.Dependencies));
            }
            return transitiveDependencies;
        }

        private DateTime OldestPublishedVulnerabilityDateTime(List<Modells.OsvResult.Vulnerability> vulnerabilities) {
            DateTime oldestPublishedVulnerabilityDateTime = DateTime.Now;
            foreach (Modells.OsvResult.Vulnerability vulnerability in vulnerabilities) {
                if (vulnerability.published < oldestPublishedVulnerabilityDateTime) {
                    oldestPublishedVulnerabilityDateTime = vulnerability.published;
                }
            }
            return oldestPublishedVulnerabilityDateTime;
        }
        private List<MPP> GetUniquePackagesFromList(List<MPP> packages) {
            List<MPP> uniquePackages = new List<MPP>();
            foreach (MPP package in packages) {
                if (!uniquePackages.Exists(pack => pack.Name.Equals(package.Name) && pack.Version.Equals(package.Version))) {
                    uniquePackages.Add(package);
                }
            }
            return uniquePackages;
        }
        #endregion
    }

}
