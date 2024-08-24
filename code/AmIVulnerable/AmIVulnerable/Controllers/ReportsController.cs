using Microsoft.AspNetCore.Mvc;
using Modells;
using Modells.OsvResult;
using MySql.Data.MySqlClient;
using Newtonsoft.Json;
using System.Data;
using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using F = System.IO.File;
using MP = Modells.Project;
using MPP = Modells.Packages.Package;
using Y = Modells.Yarn;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class ReportsController : ControllerBase {

        #region Config

        private readonly static string CLI = "cmd";
        private readonly string CLI_RM = CLI == "cmd" ? "del" : "rm";
        private DateTime lastDateTime = new DateTime();

        private readonly IConfiguration Configuration;
        public ReportsController(IConfiguration configuration) {
            Configuration = configuration;
        }

        #endregion

        #region Endpoints

        /// <summary>
        /// Generate a SimpleReport for a list of Projects
        /// </summary>
        /// <param name="mavenList"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("vulnerabilityTimeLineNpm")]
        public async Task<IActionResult> VulnerabilityTimeLineNpmYarn([FromBody] List<MP> projects) {
            List<TimeSlice> timeSeries = [];
            foreach (MP project in projects) {

                // Clone
                string dirGuid = await project.Clone();
                if (dirGuid.Equals("Err")) {
                    return BadRequest("Could not clone project!");
                }
                // npm install
                Install(dirGuid);
                // osv-scanner for latest
                OsvResult osvResultLatest = new OsvResult();
                osvResultLatest = osvResultLatest.OsvExtractVulnerabilities(dirGuid);
                // commit DateTime
                lastDateTime = GetTagDateTime(dirGuid);
                // Make tree to find if vulnerability is transitive or not
                string treeJsonPathLatest = MakeTree(dirGuid);

                timeSeries.Add(MakeTimeSlice(osvResultLatest, treeJsonPathLatest, lastDateTime, dirGuid, "release"));

                foreach (string tag in project.Tags) {
                    CheckoutTagProject(dirGuid, tag);
                    // npm install
                    Install(dirGuid);
                    // osv-scanner for latest
                    string osvJsonCurrent = OsvExtractVulnerabilities(dirGuid);
                    OsvResult osvResultCurrent = JsonConvert.DeserializeObject<OsvResult>(osvJsonCurrent) ?? new OsvResult();
                    // Make tree to find if vulnerability is transitive or not
                    string treeJsonPathCurrent = MakeTree(dirGuid);
                    timeSeries.Add(MakeTimeSlice(osvResultCurrent, treeJsonPathCurrent, lastDateTime, dirGuid, tag));
                    // commit DateTime
                    lastDateTime = GetTagDateTime(dirGuid);

                    timeSeries.Add(MakeTimeSlice(osvResultCurrent, treeJsonPathCurrent, lastDateTime, dirGuid, tag));
                    lastDateTime = lastDateTime.AddSeconds(-1);
                }
            }
            return Ok(timeSeries);
        }

        [HttpPost]
        [Route("vulnerabilityMetrics")]
        public async Task<IActionResult> VulnerabilityMetrics([FromBody] List<MP> projects) {
            List<ProjectMetricResult> projectMetricResults = new List<ProjectMetricResult>();
            foreach (MP project in projects) {
                // Clone
                string dirGuid = await project.Clone();
                if (dirGuid.Equals("Err")) {
                    return BadRequest("Could not clone project!");
                }

                // npm install
                Install(dirGuid);
                // osv-scanner for latest
                string osvJson = OsvExtractVulnerabilities(dirGuid);
                OsvResult osvResult = JsonConvert.DeserializeObject<OsvResult>(osvJson) ?? new OsvResult();
                // commit DateTime
                DateTime lastDateTime = GetTagDateTime(dirGuid);
                // Make tree to find if vulnerability is transitive or not
                string treeJsonPath = MakeTree(dirGuid);

                List<MPP> packageList = new List<MPP>();
                using (JsonDocument jsonDocument = JsonDocument.Parse(F.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + treeJsonPath))) {
                    if (jsonDocument.RootElement.TryGetProperty("dependencies", out JsonElement npmDependenciesElement) &&
                        npmDependenciesElement.ValueKind == JsonValueKind.Object) {
                        foreach (JsonProperty dependency in npmDependenciesElement.EnumerateObject()) {
                            MPP package = ExtractDependencyInfoNpm(dependency);

                            packageList.Add(package);
                        }
                    }
                }

                projectMetricResults.Add(MakeMetricResult(osvResult, treeJsonPath, lastDateTime, dirGuid, project.ProjectUrl, packageList));
            }
            return Ok(projectMetricResults);
        }

        private void Install(string dirGuid) {
            if (F.Exists(AppDomain.CurrentDomain.BaseDirectory + dirGuid + "/yarn.lock")) {
                ExecuteCommand("npx yarn", "", dirGuid);
                return;
            }
            else {
                ExecuteCommand(CLI_RM, ".npmrc", dirGuid);
                ExecuteCommand("npm", "install", dirGuid);
                ExecuteCommand("npm", "i --lockfile-version 3 --package-lock-only", dirGuid);
                return;
            }
        }

        #endregion

        #region Internal function(s)

        private DataTable ExecuteMySqlCommand(string command) {
            // MySql Connection
            MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);
            MySqlCommand cmd = new MySqlCommand(command, connection);
            DataTable dataTable = new DataTable();
            connection.Open();

            MySqlDataReader reader = cmd.ExecuteReader();
            dataTable.Load(reader);
            connection.Close();
            return dataTable;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tag"></param>
        private bool CheckoutTagProject(string dir, string tag = "-") {
            try {
                ProcessStartInfo process = new ProcessStartInfo {
                    FileName = CLI,
                    RedirectStandardInput = true,
                    WorkingDirectory = $"{AppDomain.CurrentDomain.BaseDirectory + dir}",
                };

                Process runProcess = Process.Start(process)!;
                runProcess.StandardInput.WriteLine($"git " + "stash");
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

        #region MakeTree

        /// <summary>
        /// Make a tree.json file
        /// </summary>
        /// <param name="projectUrl"></param>
        /// <param name="Tag"></param>
        /// <returns>File path</returns>
        private string MakeTree(string dirGuid) {
            if (F.Exists(AppDomain.CurrentDomain.BaseDirectory + dirGuid + "/yarn.lock")) {
                ExecuteCommand(CLI_RM, "tree.json", dirGuid);
                ExecuteCommand("npx yarn", "list --all --json > tree.json", dirGuid);
            }
            else if (F.Exists(AppDomain.CurrentDomain.BaseDirectory + dirGuid + "/package.json")) {
                ExecuteCommand(CLI_RM, "tree.json", dirGuid);
                ExecuteCommand("npm", "list --all --json > tree.json", dirGuid);
            }
            return dirGuid + "/tree.json";
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
        #endregion

        #region work functions
        /// <summary>
        /// 
        /// </summary>
        /// <param name="dir"></param>
        /// <returns></returns>
        private string OsvExtractVulnerabilities(string dir) {
            ExecuteCommand("osv-scanner", " --format json . > osv.json", dir);
            return F.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + dir + "/osv.json"); ;
        }

        private TimeSlice MakeTimeSlice(OsvResult osvResult, string treeJsonPath, DateTime timestamp, string dir, string tagName = "release") {
            TimeSlice timeSlice = new TimeSlice();

            timeSlice.TagName = tagName;
            timeSlice.Timestamp = timestamp;

            // Extract JsonTree
            List<object> packageList = new List<object>();
            using (JsonDocument jsonDocument = JsonDocument.Parse(F.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + treeJsonPath))) {
                if (jsonDocument.RootElement.TryGetProperty("dependencies", out JsonElement npmDependenciesElement) &&
                    npmDependenciesElement.ValueKind == JsonValueKind.Object) {
                    foreach (JsonProperty dependency in npmDependenciesElement.EnumerateObject()) {
                        MPP package = ExtractDependencyInfoNpm(dependency);

                        packageList.Add(package);
                    }
                }
                if (jsonDocument.RootElement.TryGetProperty("data", out JsonElement yarnDependenciesElement) &&
                    yarnDependenciesElement.ValueKind == JsonValueKind.Object) {
                    if (yarnDependenciesElement.TryGetProperty("trees", out JsonElement yarnDependenciesElementC)) {
                        foreach (JsonElement tree in yarnDependenciesElementC.EnumerateArray()) {
                            Y.Child? yarnChild = tree.Deserialize<Y.Child>();
                            if (yarnChild is not null) {
                                yarnChild = RecursiveVersionExtraction(yarnChild);
                                packageList.Add(yarnChild);
                            }
                        }
                    }
                }
            }
            timeSlice.CountDirectDependencies = packageList.Count;

            // Count all Vulnerabilities found in osv scan
            int vulnerabilityCount = 0;
            foreach (Packages osvPackage in osvResult.results[0].packages) {
                vulnerabilityCount += osvPackage.vulnerabilities.Count;
            }
            timeSlice.CountTotalFoundVulnerabilities = vulnerabilityCount;

            if (!F.Exists(AppDomain.CurrentDomain.BaseDirectory + dir + "/yarn.lock")) {
                // Make list of all transitive dependencies
                List<MPP> allTransitiveDependencies = new List<MPP>();
                foreach (MPP package in packageList) {
                    allTransitiveDependencies.AddRange(TransitiveDependencies(package.Dependencies));
                }
                timeSlice.CountTransitiveDependencies = allTransitiveDependencies.Count;

                timeSlice.CountUniqueTransitiveDependencies = GetUniquePackagesFromList(allTransitiveDependencies).Count;

                // Make list of direct vulnerabilities (Known and ToDate)
                List<MPP> allKnownDirectVulnerabilities = new List<MPP>();
                List<MPP> allToDateDirectVulnerabilities = new List<MPP>();
                foreach (MPP package in packageList) {
                    foreach (Packages vulnerablePackage in osvResult.results[0].packages) {
                        if (package.Name == vulnerablePackage.package.name && package.Version == vulnerablePackage.package.version) {
                            allToDateDirectVulnerabilities.Add(package);
                            if (timestamp >= OldestPublishedVulnerabilityDateTime(vulnerablePackage.vulnerabilities)) {
                                allKnownDirectVulnerabilities.Add(package);
                            }
                        }
                    }
                }
                timeSlice.CountKnownDirectVulnerabilities = allKnownDirectVulnerabilities.Count;
                timeSlice.CountToDateDirectVulnerabilities = allToDateDirectVulnerabilities.Count;

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
                timeSlice.CountKnownTransitiveVulnerabilities = allKnownTransitiveVulnerabilities.Count;
                timeSlice.CountToDateTransitiveVulnerabilities = allToDateTransitiveVulnerabilities.Count;

                timeSlice.CountKnownUniqueTransitiveVulnerabilities = GetUniquePackagesFromList(allKnownTransitiveVulnerabilities).Count;
                timeSlice.CountToDateUniqueTransitiveVulnerabilities = GetUniquePackagesFromList(allToDateTransitiveVulnerabilities).Count;
            }

            if (F.Exists(AppDomain.CurrentDomain.BaseDirectory + dir + "/yarn.lock")) {

                List<Y.Child> yarnAllTransitiveDependencies = new List<Y.Child>();
                foreach (Y.Child yarnPackage in packageList) {
                    yarnAllTransitiveDependencies.AddRange(YarnTransitiveDependencies(yarnPackage.children));
                }
                timeSlice.CountTransitiveDependencies = yarnAllTransitiveDependencies.Count;
                timeSlice.CountUniqueTransitiveDependencies = YarnGetUniquePackagesFromList(yarnAllTransitiveDependencies).Count;

                List<Y.Child> yarnAllKnownDirectVulnerabilities = new List<Y.Child>();
                List<Y.Child> yarnToDateDirectVulnerabilities = new List<Y.Child>();
                foreach (Y.Child yarnPackage in packageList) {
                    foreach (Packages osvPackage in osvResult.results[0].packages) {
                        if (yarnPackage.name == osvPackage.package.name && yarnPackage.version == osvPackage.package.version) {
                            yarnAllKnownDirectVulnerabilities.Add(yarnPackage);
                            if (timestamp >= OldestPublishedVulnerabilityDateTime(osvPackage.vulnerabilities)) {
                                yarnToDateDirectVulnerabilities.Add(yarnPackage);
                            }
                        }
                    }
                }
                timeSlice.CountKnownDirectVulnerabilities = yarnAllKnownDirectVulnerabilities.Count;
                timeSlice.CountToDateDirectVulnerabilities = yarnToDateDirectVulnerabilities.Count;

                List<Y.Child> yarnAllKnownTransitiveVulnerabilities = new List<Y.Child>();
                List<Y.Child> yarnAllToDateTransitiveVulnerabilities = new List<Y.Child>();
                foreach (Y.Child yarnTransitiveDependency in yarnAllTransitiveDependencies) {
                    foreach (Packages osvPackage in osvResult.results[0].packages) {
                        if (yarnTransitiveDependency.name == osvPackage.package.name && yarnTransitiveDependency.version == osvPackage.package.version) {
                            yarnAllKnownTransitiveVulnerabilities.Add(yarnTransitiveDependency);
                            if (timestamp >= OldestPublishedVulnerabilityDateTime(osvPackage.vulnerabilities)) {
                                yarnAllToDateTransitiveVulnerabilities.Add(yarnTransitiveDependency);
                            }
                        }

                    }
                }
                timeSlice.CountKnownTransitiveVulnerabilities = yarnAllKnownTransitiveVulnerabilities.Count;
                timeSlice.CountToDateTransitiveVulnerabilities = yarnAllToDateTransitiveVulnerabilities.Count;

                timeSlice.CountKnownUniqueTransitiveVulnerabilities = YarnGetUniquePackagesFromList(yarnAllKnownTransitiveVulnerabilities).Count;
                timeSlice.CountToDateUniqueTransitiveVulnerabilities = YarnGetUniquePackagesFromList(yarnAllToDateTransitiveVulnerabilities).Count;
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

        private Y.Child RecursiveVersionExtraction(Y.Child child) {
            try {
                for (int i = 0; i < child.children.Count; i += 1) {
                    child.children[i] = RecursiveVersionExtraction(child.children[i]);
                }
                child.version = child.name[(child.name.LastIndexOf('@') + 1)..child.name.Length];
                if (child.version[0] == '~' || child.version[0] == '^') {
                    child.version = child.version[1..child.version.Length];
                }
                return child;
            }
            catch {
                return child;
            }
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

        private List<Y.Child> YarnTransitiveDependencies(List<Y.Child> yarnTransitiveDependencies) {
            if (!yarnTransitiveDependencies.Any()) {
                return [];
            }
            List<Y.Child> children = new List<Y.Child>();

            foreach (Y.Child child in yarnTransitiveDependencies) {
                children.Add(child);
                if (child.children != null) {
                    children.AddRange(YarnTransitiveDependencies(child.children));
                }
            }
            return children;
        }

        private DateTime OldestPublishedVulnerabilityDateTime(List<Vulnerability> vulnerabilities) {
            DateTime oldestPublishedVulnerabilityDateTime = DateTime.Now;
            foreach (Vulnerability vulnerability in vulnerabilities) {
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

        private List<Y.Child> YarnGetUniquePackagesFromList(List<Y.Child> packages) {
            List<Y.Child> uniquePackages = new List<Y.Child>();
            foreach (Y.Child package in packages) {
                if (!uniquePackages.Exists(pack => pack.name.Equals(package.name) && pack.version.Equals(package.version))) {
                    uniquePackages.Add(package);
                }
            }
            return uniquePackages;
        }
        private ProjectMetricResult MakeMetricResult(OsvResult osvResult, string treeJsonPath, DateTime timestamp, string dir, string url, List<MPP> packageList) {
            ProjectMetricResult projectMetricResult = new ProjectMetricResult();
            projectMetricResult.AnalyseTime = timestamp;
            projectMetricResult.ProjectUrl = url;
            projectMetricResult.VulnerabilityMetrics = MakeMetrics(osvResult, treeJsonPath, dir, packageList);
            return new ProjectMetricResult();
        }
        private List<VulnerabilityMetric> MakeMetrics(OsvResult osvResult, string treeJsonPath, string dir, List<MPP> packageList) {
            List<VulnerabilityMetric> vulnerabilityMetrics = new List<VulnerabilityMetric>();
            foreach (Packages osvPackage in osvResult.results[0].packages) {
                VulnerabilityMetric vulnerabilityMetric = new VulnerabilityMetric();
                vulnerabilityMetric.PackageName = osvPackage.package.name;
                vulnerabilityMetric.PackageVersion = osvPackage.package.version;
                MPP vulnerablePackage = packageList.Find(x => x.Name == osvPackage.package.name && x.Version == osvPackage.package.version) ?? new MPP();
                //General Data
                foreach (Vulnerability vulnerability in osvPackage.vulnerabilities) {
                    foreach (Severity severity in vulnerability.severity) {
                        vulnerabilityMetric.CvssVersion.Add(severity.type);
                        vulnerabilityMetric.NistSeverity.Add(MakeNistScore(severity.score));
                        vulnerabilityMetric.MetricData.Add(MakeMetricData(severity.score, treeJsonPath, dir, vulnerability, vulnerablePackage, osvResult.results[0].packages));
                    }
                }

                //Metric Score Caluculation
                vulnerabilityMetric.MetricScore = MakeMetricScore(vulnerabilityMetric.MetricData);

                vulnerabilityMetrics.Add(vulnerabilityMetric);
            }
            return vulnerabilityMetrics;
        }

        //Metric Cube Data
        private MetricData MakeMetricData(string vector, string treeJsonPath, string dir, Vulnerability vulnerability, MPP vulnerablePackage, List<Packages> osvPackages) {
            MetricData metricData = new MetricData();
            //metricData.TransitiveDepths = 
            metricData.Vector = MakeVector(vector);
            //metricData.UsageCount = 
            List<MPP> ownDependencies = TransitiveDependencies([vulnerablePackage]);
            metricData.OwnDependenciesCount = ownDependencies.Count();

            List<MPP> ownUniqueVulnerabilities = new List<MPP>();
            foreach (Packages osvPackage in osvPackages) {
                foreach(MPP package in ownDependencies) {
                    if(package.Name == osvPackage.package.name && package.Version == osvPackage.package.version && !ownUniqueVulnerabilities.Contains(package)) {
                        ownUniqueVulnerabilities.Add(package);
                    }
                }
            }
            metricData.OwnUniqueVulnerabilitiesCount = ownUniqueVulnerabilities.Count();
            metricData.PublishedSince = vulnerability.published;
            return metricData;
        }

        //Calculate Metric Score based on list of metricData for each Vulnerable Package and its vulnerabilities (not every Vulnerability of package)
        //this is done becuase using a different package will technically result in ALL vulnerabilities of the current package being resolved
        private double MakeMetricScore(List<MetricData> metricData) {
            return 0.0;
        }

        //Nist Score using CVSS Version 3.1 Formula
        private double MakeNistScore(string vector) {
            //Do Nist Equations for CVSS_V3.1 (https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
            return 0.0;
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

            Match availabilityImpact = Regex.Match(vectorString, @"/A:+\w{1}/");
            switch (availabilityImpact.Groups[0].Value) {
                case "/A:N/": {
                        vector.AvailabilityImpact = BaseScoreMetric.None;
                        break;
                    }
                case "/A:L/": {
                        vector.AvailabilityImpact = BaseScoreMetric.Low;
                        break;
                    }
                case "/A:H/": {
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
