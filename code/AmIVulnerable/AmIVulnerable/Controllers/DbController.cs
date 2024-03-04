﻿using LiteDbLib.Controller;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Modells;
using Newtonsoft.Json;
using SerilogTimings;
using System.Text.RegularExpressions;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class DbController : ControllerBase {

        /// <summary>
        /// Get-route checking if raw cve data is in directory
        /// </summary>
        /// <returns>OK, if exists. No Content, if doesnt exist</returns>
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

        /// <summary>
        /// Get-route converting raw cve data to db data
        /// </summary>
        /// <returns>OK if successful</returns>
        [HttpGet]
        [Route("ConvertRawDirToDb")]
        public IActionResult ConvertRawFile() {
            List<string> fileList = new List<string>();
            List<int> indexToDelete = new List<int>();
            string path = $"{AppDomain.CurrentDomain.BaseDirectory}raw";
            ExploreFolder(path, fileList);

            //filter for json files
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

        /// <summary>
        /// Adds file names of all files of a folder and its subfolders to a list
        /// </summary>
        /// <param name="folderPath">path to target folder</param>
        /// <param name="fileList">list of files</param>
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

        /// <summary>
        /// Check for an cve entry of a package with all its versions
        /// </summary>
        /// <param name="packageName">Name of package to search</param>
        /// <param name="isDbSearch">true: search db, false: search raw-json</param>
        /// <param name="packageVersion">Version of package to search</param>
        /// <returns>Ok with result. NoContent if empty.</returns>
        [HttpPost]
        [Route("checkSinglePackage")]
        public IActionResult CheckSinglePackage([FromHeader] string packageName,
                                                    [FromHeader] bool isDbSearch = true,
                                                    [FromHeader] string? packageVersion = "") {
            if (packageVersion!.Equals("")) { // search all versions
                if (isDbSearch) {
                    SearchDbController searchDbController = new SearchDbController();
                    List<CveResult> res = [];
                    using(Operation.Time($"Package \"{packageName}\"")) {
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
                    return Ok(JsonConvert.SerializeObject(SearchInJson(packageName)));
                }
            }
            else {
                // TODO: search after a specific version
            }
            return Ok();
        }

        /// <summary>
        /// Search package in raw-json data
        /// </summary>
        /// <param name="packageName">Name of package to search</param>
        /// <returns>List of CveResults</returns>
        private List<CveResult> SearchInJson(string packageName) {
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
            using (Operation.Time($"Package \"{packageName}\"")) {
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
            return results;
        }

        /// <summary>
        /// Search for a list of packages
        /// </summary>
        /// <param name="packages">List of tuple: package, version</param>
        /// <returns>OK, if exists. OK, if no package list searched. NoContent if not found.</returns>
        [HttpPost]
        [Route("checkPackageList")]
        public async Task<IActionResult> CheckPackageListAsync([FromBody] List<Tuple<string, string>> packages) {
            if (packages.Count > 0) {
                SearchDbController searchDbController = new SearchDbController();
                List<CveResult> results = [];
                List<string> strings = [];
                foreach (Tuple<string, string> item in packages) {
                    strings.Add(item.Item1);
                    if (item.Item1.Equals("")) {
                        continue;
                    }
                    using (Operation.Time($"Time by mono {item.Item1}")) {
                        results.AddRange(searchDbController.SearchSinglePackage(item.Item1));
                    }
                }
                using (Operation.Time($"Time by pipe")) {
                    results = await searchDbController.SearchPackagesAsList(strings);
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
