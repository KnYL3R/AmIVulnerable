﻿using Microsoft.AspNetCore.Mvc;
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
                DeleteLocalFiles(project);
                F.WriteAllText(AppDomain.CurrentDomain.BaseDirectory + "/dependencyCache.json", JsonConvert.SerializeObject(projects));
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
                DeleteLocalFiles(project);
                F.WriteAllText(AppDomain.CurrentDomain.BaseDirectory + "/vulnerabilityCache.json", JsonConvert.SerializeObject(projects));
            }
            return Ok(projects);
        }

        [HttpPost]
        [Route("management/vulnerability")]
        public IActionResult DirectDependecyMetric([FromBody] List<ProjectDto> projectsDto) {
            List<MP> projects = new List<MP>();
            foreach (ProjectDto projectDto in projectsDto) {
                projects.Add(new MP(projectDto.ProjectUrl));
            }
            List<ProjectVulnerabilityResultMetricReturnType> projectVulnerabilityResultMetricReturnTypes = new List<ProjectVulnerabilityResultMetricReturnType>();
            foreach (MP project in projects) {
                List<VulnerabilityResultMetric> vulnerabilityResultMetrics = new List<VulnerabilityResultMetric>();
                Console.WriteLine("Now analysing: " + project.ProjectUrl);
                if (project.MakeDependencyTreeCloneAsync().Result == "FAILED") {
                    Console.WriteLine("Could not clone or install project");
                    continue;
                }
                vulnerabilityResultMetrics.AddRange(MakeVulnerabilityResultMetrics(project));
                projectVulnerabilityResultMetricReturnTypes.Add(new ProjectVulnerabilityResultMetricReturnType(project.ProjectUrl, vulnerabilityResultMetrics));
            }
            if(projectVulnerabilityResultMetricReturnTypes.Count == 0) {
                return StatusCode(500, new {
                    error = new {
                        code = 500,
                        message = "Internal Server Error",
                        details = "Could not clone or install any projects"
                    }
                });
            }
            return Ok(projectVulnerabilityResultMetricReturnTypes);
        }
        #endregion

        private List<VulnerabilityResultMetric> MakeVulnerabilityResultMetrics(MP project) {
            List<VulnerabilityResultMetric> vulnerabilityResultMetrics = new List<VulnerabilityResultMetric>();
            OsvResult osvResult = new OsvResult();
            osvResult = osvResult.OsvExtractVulnerabilities(project);
            if (osvResult.results.Count == 0) {
                return [];
            }
            foreach (Packages osvPackage in osvResult.results[0].packages) {
                foreach (OSVV osvPackageVulnerability in osvPackage.vulnerabilities) {
                    VulnerabilityResultMetric v = new VulnerabilityResultMetric();
                    foreach (PP package in project.Packages) {
                        v.packageDependencyPaths.AddRange(GetDependencyPaths(osvPackage, package));
                        v.packageTransitiveDepths.AddRange(GetDepths(osvPackage, package));
                    }
                    v.packageTransitiveDepthsPackages.AddRange(GetDepthPackages(v.packageDependencyPaths));
                    //if there is no path to the package in all prod-dependencies it is of no value to prod environments
                    //also no path means no way to the dependency --> no way to fix it!
                    if (v.packageDependencyPaths.Count == 0) {
                        continue;
                    }
                    if (osvPackageVulnerability.severity.Count != 0) {
                        v.vulnerabilityVectorString = osvPackageVulnerability.severity[0].score;
                        v.vulnerabilityVector = MakeVector(osvPackageVulnerability.severity[0].score);
                        v.vulnerabilitySeverity = v.vulnerabilityVector.BaseScore();
                    }
                    v.vulnerabilityAliases = osvPackageVulnerability.aliases;
                    v.vulnerabilitySummary = osvPackageVulnerability.summary;
                    v.vulnerabilityDetails = osvPackageVulnerability.details;
                    v.vulnerabilityReferences = osvPackageVulnerability.references;
                    v.vulnerabilityDatabaseSpecific = osvPackageVulnerability.database_specific;
                    foreach (Modells.OsvResult.Affected affected in osvPackageVulnerability.affected) {
                        v.vulnerabilityRanges.AddRange(affected.ranges);
                    }
                    v.packageName = osvPackage.package.name;
                    v.packageVersion = osvPackage.package.version;
                    v.packageSubPackagesNumber = GetSubPackagesCount(GetProjectPackage(osvPackage, project.Packages));
                    vulnerabilityResultMetrics.Add(v);
                }
            }
            return vulnerabilityResultMetrics;
        }

        private void DeleteLocalFiles(MP project) {
            RemoveReadOnlyAttribute(AppDomain.CurrentDomain.BaseDirectory + project.DirGuid);
            F.Delete(AppDomain.CurrentDomain.BaseDirectory + project.DirGuid + "/osv.json");
            F.Delete(AppDomain.CurrentDomain.BaseDirectory + project.DirGuid + "/tree.json");
            F.Delete(AppDomain.CurrentDomain.BaseDirectory + project.DirGuid + "/tags.txt");
            F.Delete(AppDomain.CurrentDomain.BaseDirectory + project.DirGuid + "/status.txt");
        }
        private static void RemoveReadOnlyAttribute(string path) {
            DirectoryInfo directoryInfo = new DirectoryInfo(path);

            foreach (FileInfo file in directoryInfo.GetFiles()) {
                file.Attributes &= ~FileAttributes.ReadOnly;
            }

            foreach (DirectoryInfo subDirectory in directoryInfo.GetDirectories()) {
                try {
                    RemoveReadOnlyAttribute(subDirectory.FullName);
                }
                catch {
                    return;
                }
            }
        }

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

        private int GetSubPackagesCount(PP dependency, int packageCount = 0) {
            packageCount += dependency.Dependencies.Count;
            foreach (PP subDependency in dependency.Dependencies) {
                packageCount += GetSubPackagesCount(subDependency, packageCount);
            }
            return packageCount;
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

        private PP GetProjectPackage(Packages osvPackage, List<PP> projectPackages) {
            foreach (PP projectPackage in projectPackages) {
                if (osvPackage.package.name == projectPackage.Name &&
                    osvPackage.package.version == projectPackage.Version) {
                    return projectPackage;
                }
                foreach (PP dependencyPackage in projectPackage.Dependencies) {
                    return GetProjectPackage(osvPackage, dependencyPackage.Dependencies);
                }
            }
            return new PP();
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

        private List<string> GetDependencyPaths(Packages osvPackage, PP package, string path = " -> ") {
            List<string> savedPaths = new List<string>();
            if (package.Name == osvPackage.package.name &&
                package.Version == osvPackage.package.version) {
                savedPaths.Add(path + package.Name);
            }
            path += package.Name + " -> ";
            foreach (PP dependencyPackage in package.Dependencies) {
                //path += dependencyPackage.Name + " -> ";
                savedPaths.AddRange(GetDependencyPaths(osvPackage, dependencyPackage, path));
            }
            return savedPaths;
        }
        private List<PP> GetDepthPackages(List<string> pathStrings) {
            List<PP> depthPackages = new List<PP>();
            foreach (string pathString in pathStrings) {
                List<string> subs = pathString.Split(" -> ").ToList();
                subs.Remove(subs.First());
                PP package = new PP();
                package.Name = subs.First();
                subs.Remove(subs.First());
                if(subs.Count != 0) {
                    package.Dependencies.Add(MakePackageFromStrings(subs));
                }
                depthPackages.Add(package);
            }
            return depthPackages;
        }

        private PP MakePackageFromStrings(List<string> subs) {
            PP newPackage = new PP();
            newPackage.Name = subs.First();
            subs.Remove(subs.First());
            if (subs.Count == 0) {
                return newPackage;
            }
            newPackage.Dependencies.Add(MakePackageFromStrings(subs));
            return newPackage;
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
