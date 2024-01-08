using LiteDb.Controller;
using Microsoft.AspNetCore.Mvc;
using Modells;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace AmIVulnerable.Controllers {

    /// <summary>
    /// Controller, that interact with the test database.
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class DbTest : ControllerBase {

        [HttpGet]
        [Route("ping")]
        public IActionResult Ping() {
            return Ok();
        }

        [HttpPost]
        [Route("contentPing")]
        public IActionResult ContentPing ([FromBody] string body) {
            if (body.Equals("DemoDummy")) {
                return Ok("Positiv");
            }
            else {
                return BadRequest();
            }
        }

        [HttpGet]
        [Route("FillSampleDatabase")]
        public IActionResult SimplePing() {
            ReachTestDbController dbConnection = new ReachTestDbController();
            dbConnection.CreateSampleData();
            return Ok();
        }

        [HttpGet]
        [Route("RequestSample")]
        public IActionResult RequestSample() {
            ReachTestDbController dbConnection = new ReachTestDbController();
            string res = dbConnection.ReadSampleData();
            if (res is "") {
                return Ok();
            }
            else {
                return BadRequest(res);
            }
        }

        [HttpDelete]
        [Route("deleteSample")]
        public IActionResult Delete() {
            ReachTestDbController dbConnection = new ReachTestDbController();
            int res = dbConnection.ResetSampleDatabase();
            if (res == 0) {
                return NoContent();
            }
            else if (res == 4) {
                return Ok();
            }
            else {
                return BadRequest(res);
            }
        }

        [HttpGet]
        [Route("testJsonFiles")]
        public IActionResult Test() {
            List<string> fileList = new List<string>();

            string pathDif = "..\\..\\..\\..\\..\\..\\..\\";
            string folderPath = AppDomain.CurrentDomain.BaseDirectory + pathDif + "cvelistV5-main";
            ExploreFolder(folderPath, fileList);

            foreach (string jsonFile in fileList) {
                if (Regex.IsMatch(jsonFile, @"CVE-[\w\S]+.json")) {
                    try {
                        string jsonContent;
                        using (StreamReader reader = new StreamReader(jsonFile)) {
                            jsonContent = reader.ReadToEnd();
                        }
                        CVEcomp test = JsonConvert.DeserializeObject<CVEcomp>(jsonContent)!;
                    }
                    catch (Exception ex) {
                        return BadRequest(ex.Message);
                    }
                }
            }

            return Ok();
        }

        private void ExploreFolder(string folderPath, List<string> fileList) {
            try {
                // Alle Dateien im aktuellen Ordner hinzufügen
                fileList.AddRange(Directory.GetFiles(folderPath));

                // Rekursiv alle Unterordner durchsuchen
                foreach (string subfolder in Directory.GetDirectories(folderPath)) {
                    ExploreFolder(subfolder, fileList);
                }
            }
            catch (Exception ex) {
                Console.WriteLine($"Fehler beim Durchsuchen des Ordners: {ex.Message}");
            }
        }
    }
}
