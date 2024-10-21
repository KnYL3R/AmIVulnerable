using Microsoft.AspNetCore.Mvc;
using Modells;
using Modells.OsvResult;
using System.Text.RegularExpressions;
using MP = Modells.Project;
using V = Modells.Vulnerability;
using OSVV = Modells.OsvResult.Vulnerability;
using System.Text.Json;
using PP = Modells.Packages.Package;
using F = System.IO.File;
using Modells.DTO;
using Newtonsoft.Json;
using Modells.Packages;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class MetricController : ControllerBase {

        #region Config

        private readonly static string CLI = "cmd";
        private readonly string CLI_RM = CLI == "cmd" ? "del" : "rm";
        private DateTime lastDateTime = new DateTime();

        private readonly IConfiguration Configuration;
        public MetricController(IConfiguration configuration) {
            Configuration = configuration;
        }

        #endregion

        #region Endpoints

        /// <summary>
        /// Generate two dimensional Metric Data for Dependencies
        /// </summary>
        /// <param name="projects"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("dependency")]
        public IActionResult Dependency([FromBody] List<ProjectDto> projectsDto) {
            List<MP> projects = new List<MP>();
            foreach (ProjectDto projectDto in projectsDto) {
                projects.Add(new MP(projectDto.ProjectUrl));
            }

            foreach (MP project in projects) {
                Console.WriteLine("Now analysing: " +  project.ProjectUrl + " || master");
                if(project.MakeDependencyTreeCloneAsync().Result == "FAILED") {
                    continue;
                }
                project.Results.Add(MakeDependencyResultEntry(project, "master"));
                project.SetTags();

                foreach (string tag in project.Tags) {
                    Console.WriteLine("Now analysing: " + project.ProjectUrl + " || " + tag);
                    if (project.MakeDependencyTreeCheckoutAsync(tag) == "FAILED") {
                        continue;
                    }
                    project.Results.Add(MakeDependencyResultEntry(project, tag));
                }
                F.WriteAllText(AppDomain.CurrentDomain.BaseDirectory + "cache.json", JsonConvert.SerializeObject(projects));
            }
            //Return list of enriched projects
            return Ok(projects);
        }

        /// <summary>
        /// Generate two dimensional Metric Data for Vulnerablilty
        /// </summary>
        /// <param name="projects"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("vulnerability")]
        public IActionResult Vulnerablilty([FromBody] List<ProjectDto> projectsDto) {
            List<MP> projects = new List<MP>();
            foreach (ProjectDto projectDto in projectsDto) {
                projects.Add(new MP(projectDto.ProjectUrl));
            }
            foreach (MP project in projects) {
                Console.WriteLine("Now analysing: " + project.ProjectUrl + " || master");
                if (project.MakeDependencyTreeCloneAsync().Result == "FAILED") {
                    continue;
                }
                project.Results.Add(MakeVulnerabilityResultEntry(project, "master"));
                project.SetTags();

                foreach (string tag in project.Tags) {
                    Console.WriteLine("Now analysing: " + project.ProjectUrl + " || " + tag);
                    if (project.MakeDependencyTreeCheckoutAsync(tag) == "FAILED") {
                        continue;
                    }
                    project.Results.Add(MakeVulnerabilityResultEntry(project, tag));
                }
            }
            return Ok(projects);
        }

        [HttpPost]
        [Route("management/vulnerabilities")]
        public IActionResult DirectDependecyMetric([FromBody] List<ProjectDto> projectsDto) {
            List<MP> projects = new List<MP>();
            foreach (ProjectDto projectDto in projectsDto) {
                projects.Add(new MP(projectDto.ProjectUrl));
            }
            List<Modells.Packages.VulnerabilityMetric> directVulnerableDependencyMetrics = new List<Modells.Packages.VulnerabilityMetric>();
            foreach (MP project in projects) {
                Console.WriteLine("Now analysing: " + project.ProjectUrl);
                if (project.MakeDependencyTreeCloneAsync().Result == "FAILED") {
                    Console.WriteLine("Could not clone or install project");
                    //directVulnerableDependencyMetrics.AddRange(GetPackageMetrics(project));
                    continue;
                }
            }
            return Ok();
        }
        #endregion

        //private List<Modells.Packages.VulnerabilityMetric> GetPackageMetrics(MP project) {
        //    List<Modells.Packages.VulnerabilityMetric> packageMetrics = new List<Modells.Packages.VulnerabilityMetric>();
        //    OsvResult osvResult = new OsvResult();
        //    osvResult = osvResult.OsvExtractVulnerabilities(project);
        //    if (osvResult.results.Count == 0) {
        //        return [];
        //    }
        //    foreach (PP directDependency in project.Packages) {
        //        packageMetrics.Add(MakePackageMetric(directDependency, osvResult));
        //    }
        //    return packageMetrics;
        //}

        //private Modells.Packages.VulnerabilityMetric MakePackageMetric(PP dependency, OsvResult osvResult) {
        //    Modells.Packages.VulnerabilityMetric packageMetric = new Modells.Packages.VulnerabilityMetric();
        //    packageMetric.version = dependency.Version;
        //    packageMetric.name = dependency.Name;
        //    return packageMetric;
        //}

        /// <summary>
        /// 
        /// </summary>
        /// <param name="project"></param>
        /// <returns></returns>
        private MP.Tag MakeDependencyResultEntry(MP project, string tagName) {
            OsvResult osvResult = new OsvResult();
            osvResult = osvResult.OsvExtractVulnerabilities(project);
            MP.Tag tagWithEntries = new MP.Tag();
            tagWithEntries.TagName = tagName;
            if (osvResult.results.Count == 0) {
                tagWithEntries.RootDependencies = [];
                return tagWithEntries;
            }

            List<List<V>> directDependencyVulnerabilities = new List<List<V>>();

            foreach (PP directDependency in project.Packages) {
                List<V> directDependencyVulnerabilitiesSubList = new List<V>();
                foreach (Packages osvPackage in osvResult.results[0].packages) {
                    List<int> transitiveDepths = GetDepths(osvPackage, directDependency);
                    foreach (int transitiveDepth in transitiveDepths) {
                        directDependencyVulnerabilitiesSubList.Add(new V(osvPackage.package.name, osvPackage.package.version, GetHighestSeverity(osvPackage.vulnerabilities), transitiveDepth));
                    }
                }
                if (directDependencyVulnerabilitiesSubList.Count != 0) {
                    directDependencyVulnerabilities.Add(directDependencyVulnerabilitiesSubList);
                    tagWithEntries.RootDependencies.Add(new MP.Rootdependency(directDependency.Name, directDependencyVulnerabilitiesSubList));
                }
            }
            return tagWithEntries;
        }

        private MP.Tag MakeVulnerabilityResultEntry(MP project, string tagName) {
            OsvResult osvResult = new OsvResult();
            osvResult = osvResult.OsvExtractVulnerabilities(project);
            MP.Tag tagWithEntries = new MP.Tag();
            tagWithEntries.TagName = tagName;
            if (osvResult.results.Count == 0) {
                tagWithEntries.RootDependencies = [];
                return tagWithEntries;
            }

            List<List<V>> vulnerabilitiesOfVulnerabilities = new List<List<V>>();
            List<PP> vulnerableDependencies = GetVulnerablePackages(osvResult.results[0].packages, project.Packages);

            foreach (PP vulnerableDependency in vulnerableDependencies) { 
                List<V> vulnerabilitiesOfVulnerabilitiesSubList = new List<V>();
                foreach(Packages osvPackage in osvResult.results[0].packages) {
                    List<int> transitiveDepths = GetDepths(osvPackage, vulnerableDependency);
                    foreach (int transitiveDepth in transitiveDepths) {
                        vulnerabilitiesOfVulnerabilitiesSubList.Add(new V(osvPackage.package.name, osvPackage.package.version, GetHighestSeverity(osvPackage.vulnerabilities), transitiveDepth));
                    }
                }
                if (vulnerabilitiesOfVulnerabilitiesSubList.Count != 0) {
                    vulnerabilitiesOfVulnerabilities.Add(vulnerabilitiesOfVulnerabilitiesSubList);
                    tagWithEntries.RootDependencies.Add(new MP.Rootdependency(vulnerableDependency.Name, vulnerabilitiesOfVulnerabilitiesSubList));
                }
            }
            return tagWithEntries;
        }

        private List<PP> GetVulnerablePackages(List<Packages> osvPackages, List<PP> projectPackages) { 
            List<PP> vulnerablePackages = new List<PP>();
            foreach(Packages osvPackage in osvPackages) {
                foreach(PP package in projectPackages) {
                    vulnerablePackages.AddRange(FindVulnerablePackages(osvPackage, package));
                }
            }
            return vulnerablePackages;
        }

        private List<PP> FindVulnerablePackages(Packages osvPackage, PP package) {
            List<PP> result = new List<PP>(); 
            if (package.Name == osvPackage.package.name &&
                package.Version == osvPackage.package.version) {
                result.Add(package);
            //Search deeper
            }
            else {
                foreach(PP dependency in package.Dependencies) {
                    result.AddRange(FindVulnerablePackages(osvPackage, dependency));
                }
            }
            return result;
        }

        #region internal functions
        /// <summary>
        /// TESTED
        /// </summary>
        /// <param name="osvPackageVulnerabilities"></param>
        /// <returns></returns>
        private decimal GetHighestSeverity(List<OSVV> osvPackageVulnerabilities) {
            decimal severity = -1.0m;
            foreach (OSVV osvVulnerability in osvPackageVulnerabilities) {
                if (osvVulnerability.severity != null) {
                    foreach (Severity osvSeverity in osvVulnerability.severity) {
                        Console.WriteLine(osvSeverity.score);
                        Console.WriteLine(MakeVector(osvSeverity.score).BaseScore());
                        decimal vulnerabilitySeverity = MakeVector(osvSeverity.score).BaseScore();
                        if (vulnerabilitySeverity > severity) {
                            severity = vulnerabilitySeverity;
                        }
                    }
                }
            }
            return severity;
        }

        /// <summary>
        /// Get Depth a single osvPackage is in deptree
        /// </summary>
        /// <param name="osvPackage"></param>
        /// <param name="treeJsonPath"></param>
        /// <returns></returns>
        private List<int> GetDepths(Packages osvPackage, PP directDependency) {
            List<int> depths = new List<int>();
            //If direct dep is vulnerable
            if (directDependency.Name == osvPackage.package.name &&
                directDependency.Version == osvPackage.package.version) {
                depths.Add(0);
            }
            //For all transitive deps
            foreach (PP package in directDependency.Dependencies) {
                depths.AddRange(GetTransitiveDepths(osvPackage, package, 1));
            }
            return depths;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="osvPackage"></param>
        /// <param name="package"></param>
        /// <param name="depth"></param>
        /// <param name="savedDepths"></param>
        /// <returns></returns>
        private List<int> GetTransitiveDepths(Packages osvPackage, PP package, int depth) {
            List<int> savedDepths = new List<int>();
            //If package is found, add it
            if (package.Name == osvPackage.package.name &&
                package.Version == osvPackage.package.version) {
                savedDepths.Add(depth);
            }
            //For all subpackages look for package with depth+1
            foreach (PP dependencyPackage in package.Dependencies) {
                savedDepths.AddRange(GetTransitiveDepths(osvPackage, dependencyPackage, depth + 1));
            }
            return savedDepths;
        }

        private int ExtractDependencyDepth(Packages osvPackage, JsonProperty dependency, int depth) {
            depth += 1;
            //When finding the correct Package return a depth
            if (dependency.Value.TryGetProperty("version", out JsonElement versionElement) &&
                dependency.Value.TryGetProperty("name", out JsonElement nameElement) &&
                versionElement.ValueKind == JsonValueKind.String &&
                osvPackage.package.name == nameElement.GetString() &&
                osvPackage.package.version == versionElement.GetString()) {
                return depth;
            }
            //When not finding the correct Package search deeper
            dependency.Value.TryGetProperty("dependencies", out JsonElement subDependenciesElement);
            foreach (JsonProperty sunDependency in subDependenciesElement.EnumerateObject()) {
                ExtractDependencyDepth(osvPackage, sunDependency, depth);
            }
            return -1;
        }

        //Make string vector to element of Vector class
        private Vector MakeVector(string vectorString) {
            Vector vector = new Vector();

            Match attackVector = Regex.Match(vectorString, @"/AV:+\w{1}/");
            switch (attackVector.Groups[0].Value) {
                case "/AV:N/": {
                        vector.AttackVector = AttackVector.Network;
                        break;
                    }
                case "/AV:A/": {
                        vector.AttackVector = AttackVector.Adjacent_Network;
                        break;
                    }
                case "/AV:L/": {
                        vector.AttackVector = AttackVector.Local;
                        break;
                    }
                case "/AV:P/": {
                        vector.AttackVector = AttackVector.Physial;
                        break;
                    }
                default: {
                        vector.AttackVector = AttackVector.Not_Available;
                        break;
                    }
            }

            Match attackComplexity = Regex.Match(vectorString, @"/AC:+\w{1}/");
            switch (attackComplexity.Groups[0].Value) {
                case "/AC:L/": {
                        vector.AttackComplexity = AttackComplexity.Low;
                        break;
                    }
                case "/AC:H/": {
                        vector.AttackComplexity = AttackComplexity.High;
                        break;
                    }
                default: {
                        vector.AttackComplexity = AttackComplexity.Not_Available;
                        break;
                    }
            }

            Match privilegesRequired = Regex.Match(vectorString, @"/PR:+\w{1}/");
            switch (privilegesRequired.Groups[0].Value) {
                case "/PR:N/": {
                        vector.PrivilegesRequired = PrivilegesRequired.None;
                        break;
                    }
                case "/PR:L/": {
                        vector.PrivilegesRequired = PrivilegesRequired.Low;
                        break;
                    }
                case "/PR:H/": {
                        vector.PrivilegesRequired = PrivilegesRequired.High;
                        break;
                    }
                default: {
                        vector.PrivilegesRequired = PrivilegesRequired.Not_Available;
                        break;
                    }
            }

            Match userInteraction = Regex.Match(vectorString, @"/UI:+\w{1}/");
            switch (userInteraction.Groups[0].Value) {
                case "/UI:N/": {
                        vector.UserInteraction = UserInteraction.None;
                        break;
                    }
                case "/UI:R/": {
                        vector.UserInteraction = UserInteraction.Required;
                        break;
                    }
                default: {
                        vector.UserInteraction = UserInteraction.Not_Available;
                        break;
                    }
            }

            Match scope = Regex.Match(vectorString, @"/S:+\w{1}/");
            switch (scope.Groups[0].Value) {
                case "/S:U/": {
                        vector.Scope = Scope.Unchanged;
                        break;
                    }
                case "/S:C/": {
                        vector.Scope = Scope.Changed;
                        break;
                    }
                default: {
                        vector.Scope = Scope.Not_Available;
                        break;
                    }
            }

            Match confidentialityImpact = Regex.Match(vectorString, @"/C:+\w{1}/");
            switch (confidentialityImpact.Groups[0].Value) {
                case "/C:N/": {
                        vector.ConfidentialityImpact = BaseScoreMetric.None;
                        break;
                    }
                case "/C:L/": {
                        vector.ConfidentialityImpact = BaseScoreMetric.Low;
                        break;
                    }
                case "/C:H/": {
                        vector.ConfidentialityImpact = BaseScoreMetric.High;
                        break;
                    }
                default: {
                        vector.ConfidentialityImpact = BaseScoreMetric.Not_Available;
                        break;
                    }
            }

            Match integrityImpact = Regex.Match(vectorString, @"/I:+\w{1}/");
            switch (integrityImpact.Groups[0].Value) {
                case "/I:N/": {
                        vector.IntegrityImpact = BaseScoreMetric.None;
                        break;
                    }
                case "/I:L/": {
                        vector.IntegrityImpact = BaseScoreMetric.Low;
                        break;
                    }
                case "/I:H/": {
                        vector.IntegrityImpact = BaseScoreMetric.High;
                        break;
                    }
                default: {
                        vector.IntegrityImpact = BaseScoreMetric.Not_Available;
                        break;
                    }
            }

            Match availabilityImpact = Regex.Match(vectorString, @"/A:+\w{1}/{0,1}");
            switch (availabilityImpact.Groups[0].Value) {
                case "/A:N": {
                        vector.AvailabilityImpact = BaseScoreMetric.None;
                        break;
                    }
                case "/A:L": {
                        vector.AvailabilityImpact = BaseScoreMetric.Low;
                        break;
                    }
                case "/A:H": {
                        vector.AvailabilityImpact = BaseScoreMetric.High;
                        break;
                    }
                default: {
                        vector.AvailabilityImpact = BaseScoreMetric.Not_Available;
                        break;
                    }
            }
            return vector;
        }
        #endregion
    }
}
