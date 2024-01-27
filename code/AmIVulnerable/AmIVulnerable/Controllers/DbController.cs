using LiteDbLib.Controller;
using Microsoft.AspNetCore.Mvc;
using Modells;
using Newtonsoft.Json;
using SerilogTimings;
using System.Text.RegularExpressions;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class DbController : ControllerBase {

        [HttpGet]
        [Route("CheckRawDir")]
        public IActionResult IsRawDataThere() {
            string path = $"{AppDomain.CurrentDomain.BaseDirectory}raw";
            DirectoryInfo directoryInfo = new DirectoryInfo(path);
            if (directoryInfo.GetDirectories().Length != 0) {
                return Ok();
            }
            else {
                return NoContent();
            }
        }

        [HttpGet]
        [Route("ConvertRawDirToDb")]
        public IActionResult ConvertRawFile() {
            List<string> fileList = new List<string>();
            List<int> indexToDelete = new List<int>();
            string path = $"{AppDomain.CurrentDomain.BaseDirectory}raw";
            ExploreFolder(path, fileList);

            foreach (int i in Enumerable.Range(0, fileList.Count)) {
                if (!Regex.IsMatch(fileList[i], @"CVE-[-\S]+.json")) {
                    indexToDelete.Add(i);
                }
            }
            foreach (int i in Enumerable.Range(0, indexToDelete.Count)) {
                fileList.RemoveAt(indexToDelete[i] - i);
            }
            ConvertCveToDbController ccdbc = new ConvertCveToDbController(fileList);

            using (Operation.Time($"Konvertieren der Datenbank")) {
                ccdbc.ConvertRawCve();
            }

            return Ok();
        }

        private static void ExploreFolder(string folderPath, List<string> fileList) {
            try {
                fileList.AddRange(Directory.GetFiles(folderPath));

                foreach (string subfolder in Directory.GetDirectories(folderPath)) {
                    ExploreFolder(subfolder, fileList);
                }
            }
            catch (Exception ex) {
                Console.WriteLine($"{ex.Message}");
            }
        }

        [HttpGet, Route("checkSinglePackage")]
        public IActionResult CheckSinglePackage([FromHeader] string packageName,
                                                    [FromHeader] bool isDbSearch = true,
                                                    [FromHeader] string? packageVersion = "") {
            if (packageVersion!.Equals("")) { // search all versions
                if (isDbSearch) {
                    SearchDbController searchDbController = new SearchDbController();
                    List<CveResult> res = [];
                    using(Operation.Time($"{packageName}")) {
                        res = searchDbController.SearchSinglePackage(packageName);
                    }
                    if (res.Count > 0) {
                        return Ok(JsonConvert.SerializeObject(res));
                    }
                    else {
                        return NoContent();
                    }
                }
                else {
                    // find all json files of cve
                    List<string> fileList = new List<string>();
                    List<int> indexToDelete = new List<int>();
                    string path = $"{AppDomain.CurrentDomain.BaseDirectory}raw";
                    ExploreFolder(path, fileList);

                    foreach (int i in Enumerable.Range(0, fileList.Count)) {
                        if (!Regex.IsMatch(fileList[i], @"CVE-[-\S]+.json")) {
                            indexToDelete.Add(i);
                        }
                    }
                    foreach (int i in Enumerable.Range(0, indexToDelete.Count)) {
                        fileList.RemoveAt(indexToDelete[i] - i);
                    }
                    // search in the files
                    List<CveResult> results = [];
                    using (Operation.Time($"Packge \"{packageName}\"")) {
                        int start = 0;
                        foreach (int i in Enumerable.Range(start, fileList.Count - start)) {
                            CVEcomp item = JsonConvert.DeserializeObject<CVEcomp>(System.IO.File.ReadAllText(fileList[i]))!;
                            if (i % 100 == 0) {
                                Console.WriteLine(fileList[i] + " - " + i);
                            }
                            if (item.containers.cna.affected is null || item.containers.cna.affected.Any(x => x.product is null)) {
                                continue;
                            }
                            if (item.containers.cna.affected.Any(y => y.product.Equals(packageName))) {
                                foreach (int j in Enumerable.Range(0, item.containers.cna.affected.Count)) {
                                    foreach (Modells.Version version in item.containers.cna.affected[j].versions) {
                                        results.Add(new CveResult() {
                                            CveNumber = item.cveMetadata.cveId,
                                            Version = version.version,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    return Ok(JsonConvert.SerializeObject(results));
                }
            }
            else {
                // TODO: search after a specific version
            }
            return Ok();
        }

        [HttpGet]
        [Route("checkPackageList")]
        public IActionResult CheckPackageList([FromBody] List<Tuple<string, string>> packages) {
            if (packages.Count > 0) {
                List<CveResult> results = [];
                foreach (Tuple<string, string> item in packages) {
                    if (item.Item1.Equals("")) {
                        continue;
                    }
                    SearchDbController searchDbController = new SearchDbController();
                    using (Operation.Time($"")) {
                        results.AddRange(searchDbController.SearchSinglePackage(item.Item1));
                    }
                }
                if (results.Count > 0) {
                    return Ok(JsonConvert.SerializeObject(results));
                }
                else {
                    return NoContent();
                }
            }
            return Ok("No package List delivered.");
        }
    }
}
