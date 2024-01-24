using LiteDB;
using Modells;
using System.Collections;
using System.Collections.Generic;
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
            DirectoryInfo currentDirectory = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory + CM.AppSettings["PathToDbs"]);
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
    }
}
