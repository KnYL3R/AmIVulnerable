﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Elfie.Diagnostics;
using Modells;
using MySql.Data.MySqlClient;
using Newtonsoft.Json;
using NuGet.Protocol.Plugins;
using SerilogTimings;
using System.Data;
using System.Diagnostics;
using System.Text.RegularExpressions;
using CM = System.Configuration.ConfigurationManager;

namespace AmIVulnerable.Controllers {

    /// <summary>Interact direct with the database, like create the cve-table or request packages.</summary>
    [Route("api/[controller]")]
    [ApiController]
    public class DbController : ControllerBase {

        #region Config
        private readonly IConfiguration Configuration;

        public DbController(IConfiguration configuration) {
            Configuration = configuration;
        }
        #endregion

        #region Controller
        /// <summary>Get-route checking if raw cve data is in directory.</summary>
        /// <returns>OK, if exists. No Content, if doesnt exist</returns>
        [HttpGet]
        [Route("CheckRawDir")]
        public IActionResult IsRawDataThere() {
            string path = "raw";
            DirectoryInfo directoryInfo = new DirectoryInfo(path);
            if (directoryInfo.GetDirectories().Length != 0) {
                return Ok();
            }
            else {
                return NoContent();
            }
        }

        /// <summary>By call the raw cve.json's will be inserted in the MySql-Database.</summary>
        /// <returns>The status, if the database is finished created.</returns>
        [HttpGet]
        [Route("ConvertRawCveToDb")]
        public IActionResult ConvertRawFilesToMySql() {
            using (Operation.Time("ConvertRawCveToDb")) {
                List<string> fileList = new List<string>();
                List<int> indexToDelete = new List<int>();
                string path = "raw";
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

                try {
                    // MySql Connection
                    MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);

                    // Create the Table cve.cve if it is not already there.
                    MySqlCommand cmdTable = new MySqlCommand("" +
                        "CREATE TABLE IF NOT EXISTS cve.cve(" +
                        "cve_number VARCHAR(20) PRIMARY KEY NOT NULL," +
                        "designation VARCHAR(500) NOT NULL," +
                        "version_affected TEXT NOT NULL," +
                        "full_text MEDIUMTEXT NOT NULL" +
                        ")", connection);
                    connection.Open();
                    cmdTable.ExecuteNonQuery();
                    connection.Close();

                    int insertIndex = 0;
                    foreach (string x in fileList) {
                        string insertIntoString = "INSERT INTO cve(cve_number, designation, version_affected, full_text) VALUES(@cve, @des, @ver, @ful)";
                        MySqlCommand cmdInsert = new MySqlCommand(insertIntoString, connection);

                        string json = System.IO.File.ReadAllText(x);
                        CVEcomp cve = JsonConvert.DeserializeObject<CVEcomp>(json)!;

                        string affected = "";
                        foreach (Affected y in cve.containers.cna.affected) {
                            foreach (Modells.Version z in y.versions) {
                                affected += z.version + $"({z.status}) |";
                            }
                        }
                        if (affected.Length > 25_000) {
                            affected = "to long -> view full_text";
                        }
                        string product = "n/a";
                        try {
                            product = cve.containers.cna.affected[0].product;
                            if (product.Length > 500) {
                                product = product[0..500];
                            }
                        }
                        catch {
                            product = "n/a";
                        }
                        cmdInsert.Parameters.AddWithValue("@cve", cve.cveMetadata.cveId);
                        cmdInsert.Parameters.AddWithValue("@des", product);
                        cmdInsert.Parameters.AddWithValue("@ver", affected);
                        cmdInsert.Parameters.AddWithValue("@ful", JsonConvert.SerializeObject(cve, Formatting.None));

                        connection.Open();
                        insertIndex += cmdInsert.ExecuteNonQuery();
                        connection.Close();
                    }

                    connection.Open();
                    MySqlCommand cmdIndexCreated = new MySqlCommand("CREATE INDEX idx_designation ON cve (designation);", connection);
                    cmdIndexCreated.ExecuteNonQuery();
                    connection.Close();

                    return Ok(insertIndex);
                }
                catch (Exception ex) {
                    return BadRequest(ex.StackTrace + "\n\n" + ex.Message);
                }
            }
        }

        /// <summary></summary>
        /// <returns></returns>
        [HttpGet]
        [Route("")]
        public IActionResult UpdateCveDatabase() {
            using (Operation.Time("UpdateCveDatabase")) {
                try {
                    // MySql Connection
                    MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);

                    MySqlCommand cmdTestIfTableExist = new MySqlCommand($"" +
                        $"SELECT COUNT(*) " +
                        $"FROM information_schema.TABLES" +
                        $"WHERE (TABLE_SCHEMA = 'cve') AND (TABLE_NAME = 'cve')", connection);
                    
                    connection.Open();
                    int count = cmdTestIfTableExist.ExecuteNonQuery();
                    connection.Close();

                    if (count == 0) {
                        return BadRequest("Table not exist!\nPlease download the cve and create a database before try to update it.");
                    }

                    //start update process
                    try {
                        ProcessStartInfo process = new ProcessStartInfo {
                            FileName = "cmd",
                            RedirectStandardInput = true,
                            WorkingDirectory = $"",
                        };

                        Process runProcess = Process.Start(process)!;
                        runProcess.StandardInput.WriteLine($"git " +
                            $"clone {CM.AppSettings["StandardCveUrlPlusTag"]!} " +  // git url
                            $"raw");                                                // target dir
                        runProcess.StandardInput.WriteLine($"exit");
                        runProcess.WaitForExit();
                    }
                    catch (Exception ex) {
                        return BadRequest(ex.StackTrace);
                    }

                    //read the file List
                    List<string> fileList = new List<string>();
                    List<int> indexToDelete = new List<int>();
                    string path = "raw";
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

                    // Drop Index for faster insert
                    MySqlCommand cmdIndexDrop = new MySqlCommand("DROP INDEX idx_designation ON cve;", connection);
                    
                    connection.Open();
                    cmdIndexDrop.ExecuteNonQuery();
                    connection.Close();

                    //start insert/update in MySQL
                    int insertAndUpdateIndex = 0;
                    foreach (string x in fileList) {
                        string insertIntoString = "INSERT INTO cve(cve_number, designation, version_affected, full_text) " +
                            "VALUES(@cve, @des, @ver, @ful) " +
                            "ON DUPLICATE KEY UPDATE " +
                            "version_affected = @ver" +
                            "full_text = @ful";
                        MySqlCommand cmdInsert = new MySqlCommand(insertIntoString, connection);

                        string json = System.IO.File.ReadAllText(x);
                        CVEcomp cve = JsonConvert.DeserializeObject<CVEcomp>(json)!;

                        string affected = "";
                        foreach (Affected y in cve.containers.cna.affected) {
                            foreach (Modells.Version z in y.versions) {
                                affected += z.version + $"({z.status}) |";
                            }
                        }
                        if (affected.Length > 25_000) {
                            affected = "to long -> view full_text";
                        }
                        string product = "n/a";
                        try {
                            product = cve.containers.cna.affected[0].product;
                            if (product.Length > 500) {
                                product = product[0..500];
                            }
                        }
                        catch {
                            product = "n/a";
                        }
                        cmdInsert.Parameters.AddWithValue("@cve", cve.cveMetadata.cveId);
                        cmdInsert.Parameters.AddWithValue("@des", product);
                        cmdInsert.Parameters.AddWithValue("@ver", affected);
                        cmdInsert.Parameters.AddWithValue("@ful", JsonConvert.SerializeObject(cve, Formatting.None));

                        connection.Open();
                        insertAndUpdateIndex += cmdInsert.ExecuteNonQuery();
                        connection.Close();
                    }

                    connection.Open();
                    MySqlCommand cmdIndexCreated = new MySqlCommand("CREATE INDEX idx_designation ON cve (designation);", connection);
                    cmdIndexCreated.ExecuteNonQuery();
                    connection.Close();

                    return Ok(insertAndUpdateIndex);
                }
                catch (Exception ex) {
                    return BadRequest(ex.StackTrace + "\n\n" + ex.Message);
                }
            }
        }

        /// <summary></summary>
        /// <param name="cve_number"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("getFullTextFromCveNumber")]
        public IActionResult GetFullTextCve([FromHeader] string? cve_number) {
            using (Operation.Time("GetFullTextCve")) {
                if (cve_number is null) {
                    return BadRequest("Empty Header");
                }
                try {
                    // MySql Connection
                    MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);

                    connection.Open();
                    MySqlCommand cmdIndexCreated = new MySqlCommand($"" +
                        $"SELECT full_text " +
                        $"FROM cve.cve " +
                        $"WHERE cve_number = '{cve_number}';", connection);
                    MySqlDataReader reader = cmdIndexCreated.ExecuteReader();
                    DataTable resDataTable = new DataTable();
                    resDataTable.Load(reader);
                    connection.Close();

                    if (resDataTable.Rows.Count == 0) {
                        return NoContent();
                    }

                    return Ok(JsonConvert.SerializeObject(resDataTable.Rows[0]["full_text"].ToString()));
                }
                catch (Exception ex) {
                    return BadRequest(ex.StackTrace + "\n\n" + ex.Message);

                }
            }
        }

        /// <summary>Check for an cve entry of a package with all its versions</summary>
        /// <param name="packageName">Name of package to search</param>
        /// <param name="isDbSearch">true: search db, false: search raw-json</param>
        /// <param name="packageVersion">Version of package to search</param>
        /// <returns>Ok with result. NoContent if empty.</returns>
        [HttpPost]
        [Route("checkSinglePackage")]
        public IActionResult CheckSinglePackage([FromHeader] string packageName,
                                                    [FromHeader] bool isDbSearch = true,
                                                    [FromHeader] string? packageVersion = "") {
            if (isDbSearch) {
                using (Operation.Time($"Complete Time for Query-SingleSearch after Package \"{packageName}\"")) {
                    List<CveResult> results = [];
                    DataTable dtResult = SearchInMySql(packageName);
                    // convert the result
                    foreach (DataRow x in dtResult.Rows) {
                        CveResult y = new CveResult() {
                            CveNumber = x["cve_number"].ToString() ?? "",
                            Designation = x["designation"].ToString() ?? "",
                            Version = x["version_affected"].ToString() ?? ""
                        };
                        CVEcomp temp = JsonConvert.DeserializeObject<CVEcomp>(x["full_text"].ToString() ?? string.Empty) ?? new CVEcomp();
                        try {
                            y.CvssV31 = temp.containers.cna.metrics[0].cvssV3_1;
                            y.Description = temp.containers.cna.descriptions[0];
                        }
                        finally {
                            results.Add(y);
                        }
                    }
                    // return's
                    if (results.Count > 0) {
                        return Ok(JsonConvert.SerializeObject(results));
                    }
                    else {
                        return NoContent();
                    }
                }
            }
            else {
                // find all json files of cve                    
                return Ok(JsonConvert.SerializeObject(SearchInJson(packageName)));
            }
            #region oldcode
            //if (packageVersion!.Equals("")) { // search all versions
            //    if (isDbSearch) {
            //        SearchDbController searchDbController = new SearchDbController();
            //        List<CveResult> res = [];
            //        using (Operation.Time($"Package \"{packageName}\"")) {
            //            res = searchDbController.SearchSinglePackage(packageName);
            //        }
            //        if (res.Count > 0) {
            //            return Ok(JsonConvert.SerializeObject(res));
            //        }
            //        else {
            //            return NoContent();
            //        }
            //    }
            //    else {
            //        // find all json files of cve                    
            //        return Ok(JsonConvert.SerializeObject(SearchInJson(packageName)));
            //    }
            //}
            //else {
            //    // TODO: search after a specific version
            //}
            //return Ok();
            #endregion
        }

        /// <summary>
        /// Search for a list of packages
        /// </summary>
        /// <param name="packages">List of tuple: package, version</param>
        /// <returns>OK, if exists. OK, if no package list searched. NoContent if not found.</returns>
        [HttpPost]
        [Route("checkPackageList")]
        public async Task<IActionResult> CheckPackageListAsync([FromBody] List<Tuple<string, string>> packages) {
            List<CveResult> results = [];
            using (Operation.Time($"Complete Time for Query-Search after List of Packages")) {
                foreach (Tuple<string, string> x in packages) {
                    DataTable dtResult = SearchInMySql(x.Item1);
                    // convert the result
                    foreach(DataRow y in dtResult.Rows) {
                        CveResult z = new CveResult() {
                            CveNumber = y["cve_number"].ToString() ?? "",
                            Designation = y["designation"].ToString() ?? "",
                            Version = y["version_affected"].ToString() ?? ""
                        };
                        CVEcomp temp = JsonConvert.DeserializeObject<CVEcomp>(y["full_text"].ToString() ?? string.Empty) ?? new CVEcomp();
                        try {
                            z.CvssV31 = temp.containers.cna.metrics[0].cvssV3_1;
                            z.Description = temp.containers.cna.descriptions[0];
                        }
                        finally {
                            results.Add(z);
                        }
                    }
                }
            }
            return Ok(results.Count == 0 ? "No result" : JsonConvert.SerializeObject(results));
            #region oldcode
            //if (packages.Count > 0) {
            //    SearchDbController searchDbController = new SearchDbController();
            //    List<CveResult> resultsOld = [];
            //    List<string> strings = [];
            //    foreach (Tuple<string, string> item in packages) {
            //        strings.Add(item.Item1);
            //        if (item.Item1.Equals("")) {
            //            continue;
            //        }
            //        using (Operation.Time($"Time by mono {item.Item1}")) {
            //            resultsOld.AddRange(searchDbController.SearchSinglePackage(item.Item1));
            //        }
            //    }
            //    using (Operation.Time($"Time by pipe")) {
            //        resultsOld = await searchDbController.SearchPackagesAsList(strings);
            //    }
            //    if (resultsOld.Count > 0) {
            //        return Ok(JsonConvert.SerializeObject(resultsOld));
            //    }
            //    else {
            //        return NoContent();
            //    }
            //}
            //return Ok("No package List delivered.");
            #endregion
        }
        #endregion

        #region Internal function(s)
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

        /// <summary>Search package in raw-json data</summary>
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

        private DataTable SearchInMySql(string packageName) {
            // MySql Connection
            MySqlConnection connection = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);

            MySqlCommand cmd = new MySqlCommand($"" +
                $"SELECT cve_number, designation, version_affected, full_text " +
                $"FROM cve.cve " +
                $"WHERE designation='{packageName}';", connection);

            DataTable dataTable = new DataTable();
            using (Operation.Time($"Query-Time for Package \"{packageName}\"")) {
                // read the result
                connection.Open();
                MySqlDataReader reader = cmd.ExecuteReader();
                dataTable.Load(reader);
                connection.Close();
            }
            return dataTable;
        }
        #endregion
    }
}
