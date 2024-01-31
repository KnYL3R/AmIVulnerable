using LiteDB;
using Modells;
using System.Text.RegularExpressions;
using CM = System.Configuration.ConfigurationManager;

namespace LiteDbLib.Controller {

    public class SearchDbController {

        #region Config
        /// <summary>Return the location, where the database is located.</summary>
        private string saveDir {
            get {
                if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "Data")) {
                    Directory.CreateDirectory(AppDomain.CurrentDomain.BaseDirectory + "Data");
                }
                return (AppDomain.CurrentDomain.BaseDirectory + "Data");
            }
        }

        private List<string> dbFiles = new List<string>();

        /// <summary>Define the name of the table.</summary>
        private readonly string tableName = "cve";
        #endregion


        /// <summary></summary>
        /// <returns></returns>
        public SearchDbController() {
            Regex yearDb = new Regex(@"(\d{4}).litedb");
            DirectoryInfo currentDirectory = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory
                                                               + CM.AppSettings["PathToDbs"]);
            FileInfo[] files = currentDirectory.GetFiles();

            foreach (FileInfo file in files) {
                dbFiles.Add(file.Name);
            }
        }

        /// <summary></summary>
        /// <returns></returns>
        public List<CveResult> SearchSinglePackage(string designation) {
            List<CveResult> results = [];
            foreach (string dbFile in dbFiles) {
                Console.WriteLine($"Akutell - {dbFile}");
                using (LiteDatabase db = new LiteDatabase($"{saveDir}\\{dbFile}")) {
                    ILiteCollection<CVEcomp> col = db.GetCollection<CVEcomp>(tableName);

                    IEnumerator<CVEcomp> pointer = col.Query().ToEnumerable().GetEnumerator();

                    while (pointer.MoveNext()) {
                        CVEcomp item = pointer.Current;
                        if (item.containers.cna.affected is null || item.containers.cna.affected.Any(x => x.product is null)) {
                            continue;
                        }
                        if (item.containers.cna.affected.Any(y => y.product.Equals(designation))) {
                            foreach (int i in Enumerable.Range(0, item.containers.cna.affected.Count)) {
                                foreach (Modells.Version version in item.containers.cna.affected[i].versions) {
                                    results.Add(new CveResult() {
                                        CveNumber = item.cveMetadata.cveId,
                                        Version = version.version,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            return results;
        }

        public async Task<List<CveResult>> SearchPackagesAsList(List<string> designations) {
            List<CveResult> results = [];
            int pipeCount = 0;
            foreach (int i in Enumerable.Range(0, designations.Count)) {
                if (pipeCount < (designations.Count - 1)) { // fill pipe
                    int j = i;
                    int k = dbFiles.Count - 1;
                    while (j >= 0 && k >= 0) {
                        Task<List<CveResult>>[] tasks = new Task<List<CveResult>>[j + 1];
                        foreach (int k2 in Enumerable.Range(0, dbFiles.Count - 1)) {
                            string db = dbFiles[k];
                            string des = designations[j];
                            tasks[k2] = Task.Run(() => SearchInDb(db, des));
                            k -= 1; j -= 1;
                            if (j < 0) {
                                break;
                            }
                        }
                        await Console.Out.WriteLineAsync(); // only for debug check
                        List<CveResult>[] res = await Task.WhenAll(tasks);
                        foreach (List<CveResult> x in res) {
                            results.AddRange(x);
                        }
                    }
                    pipeCount += 1;
                }
                else if (
                        (
                            (designations.Count > dbFiles.Count) && ((pipeCount - dbFiles.Count) < dbFiles.Count)
                        ) // more designations, so check the dbCounter
                        ||
                        (
                            (designations.Count < dbFiles.Count) && (pipeCount - designations.Count) < designations.Count)
                        ) // more dbFiles, so check the designationCounter
                        { // fill the pipe with new items and remove old
                    // TODO
                    pipeCount += 1;
                }
                else { // drain the pipe
                    // TODO
                    pipeCount += 1;
                }
                //if (i < (designations.Count - 1)) {
                // stand above at fill pipe
                //}
                //else {
                //    int j = i;
                //    int k = dbFiles.Count - 1;
                //    int runCount = 0;
                //    int endCount = 1;
                //    int range = j - k;
                //    //while (j >= j - range) {
                //    while (true) {
                //            Task<List<CveResult>>[] tasks = new Task<List<CveResult>>[j + 1];
                //        foreach (int k2 in Enumerable.Range(0, dbFiles.Count - 1)) {
                //            string db = dbFiles[k];
                //            string des = designations[j];
                //            tasks[k2] = Task.Run(() => SearchInDb(db, des));
                //            k -= 1; j -= 1;
                //            if (k == 0) {
                //                runCount += 1;
                //                j = i;
                //                k = dbFiles.Count - 1 - endCount;
                //                if (k == -1) {
                //                    break;
                //                }
                //                if (endCount != range) {
                //                    endCount += 1;
                //                }
                //                continue;
                //            }
                //        }
                //        await Console.Out.WriteLineAsync(); // only for debug check
                //        List<CveResult>[] res = await Task.WhenAll(tasks);
                //        foreach (List<CveResult> x in res) {
                //            results.AddRange(x);
                //        }
                //    }
                //}
            }
            return results;
        }

        private async Task<List<CveResult>> SearchInDb(string dbFile, string designation) {
            await Console.Out.WriteLineAsync($"{dbFile} search for {designation}"); // only for debug check
            List<CveResult> results = [];
            using (LiteDatabase db = new LiteDatabase($"{saveDir}\\{dbFile}")) {
                ILiteCollection<CVEcomp> col = db.GetCollection<CVEcomp>(tableName);

                IEnumerator<CVEcomp> pointer = col.Query().ToEnumerable().GetEnumerator();

                while (pointer.MoveNext()) {
                    CVEcomp item = pointer.Current;
                    if (item.containers.cna.affected is null || item.containers.cna.affected.Any(x => x.product is null)) {
                        continue;
                    }
                    if (item.containers.cna.affected.Any(y => y.product.Equals(designation))) {
                        foreach (int i in Enumerable.Range(0, item.containers.cna.affected.Count)) {
                            foreach (Modells.Version version in item.containers.cna.affected[i].versions) {
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
    }
}
