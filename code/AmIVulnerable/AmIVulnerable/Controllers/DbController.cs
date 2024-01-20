using LiteDbLib.Controller;
using Microsoft.AspNetCore.Mvc;
using Modells;
using Newtonsoft.Json;
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
            if (directoryInfo.GetDirectories().Count() != 0) {
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
            ccdbc.ConvertRawCve();

            return Ok();
        }

        private void ExploreFolder(string folderPath, List<string> fileList) {
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
            if (packageVersion.Equals("")) { // search all versions
                if (isDbSearch) {
                    SearchDbController searchDbController = new SearchDbController();
                    List<CveResult> res = searchDbController.SearchSinglePackage(packageName);
                    if (res.Count > 0) {
                        return Ok(JsonConvert.SerializeObject(res));
                    }
                    else {
                        return NoContent();
                    }
                }
            }
            else {

            }
            return Ok();
        }
    }
}
