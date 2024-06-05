using Microsoft.AspNetCore.Mvc;
using Modells;
using Modells.Packages;
using NuGet.Protocol;
using System.Diagnostics;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class ReportsController : ControllerBase {

        /// <summary>
        /// Generate a SimpleReport for a list of Projects
        /// </summary>
        /// <param name="mavenList"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("simpleAnalyseMavenList")]
        public IActionResult SimpleAnalyseMavenList([FromBody] List<Modells.Project> mavenList) {
            List<SimpleReportLine> simpleReport = [];
            foreach (Project maven in mavenList) {
                foreach(String tag in maven.Tags) {
                    List<PackageResult> depTreeRelease = AnalyseTree(ExtractTree(MakeTree(maven.ProjectUrl, tag)), "release");
                    List<PackageResult> depTreeCurrent = AnalyseTree(ExtractTree(MakeTree(maven.ProjectUrl, tag)), "current");
                    simpleReport.Add(GenerateSimpleReportLine(depTreeRelease, depTreeCurrent));
                }
            }
            return Ok(simpleReport);
        }

        /// <summary>
        /// Make a tree.json file
        /// </summary>
        /// <param name="projectUrl"></param>
        /// <param name="Tag"></param>
        /// <returns></returns>
        private string MakeTree(string projectUrl, string Tag) {
            ExecuteCommand("mvnw", "install", "");
            return "";
        }

        /// <summary>
        /// Extract internal representation of tree from tree.json
        /// </summary>
        /// <param name="treeFilePath"></param>
        /// <returns></returns>
        private List<Package> ExtractTree(string treeFilePath) {
            return [];
        }

        /// <summary>
        /// Check Package list agains cve data, differentiate between current cve database and past versions through cveVersion
        /// </summary>
        /// <param name="packageList"></param>
        /// <param name="cveVersion"></param>
        /// <returns></returns>
        private List<PackageResult> AnalyseTree(List<Package> packageList, string cveVersion) {
            if(cveVersion == "release") {
                return [];

            } else if(cveVersion == "current") {
                return [];
            }
            else {
                return [];
            }
            //Needs to compare designations AND versions of Used Packages with Cve
            //Compare on cve database at the time AND
            //Compare on cve database now
        }

        private SimpleReportLine GenerateSimpleReportLine(List<PackageResult> releaseVulnerabilitiesList, List<PackageResult> currentVulnerabilitiesList) {
            return new SimpleReportLine();
        }

        /// <summary>
        /// Starts a process that runs a command.
        /// </summary>
        /// <param name="prog">Programm used for commands</param>
        /// <param name="command">Command used for programm</param>
        private void ExecuteCommand(string prog, string command, string dir) {
            ProcessStartInfo process = new ProcessStartInfo {
                FileName = "cmd",
                RedirectStandardInput = true,
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory + dir,
            };
            Process runProcess = Process.Start(process)!;
            runProcess.StandardInput.WriteLine($"{prog} {command}");
            runProcess.StandardInput.WriteLine($"exit");
            runProcess.WaitForExit();
        }
    }

}
