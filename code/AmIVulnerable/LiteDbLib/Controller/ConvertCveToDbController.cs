using LiteDB;
using Modells;
using Newtonsoft.Json;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Channels;

namespace LiteDbLib.Controller {

    public class ConvertCveToDbController {

        #region Config
        /// <summary>Return the location, where the database is located.</summary>
        private string saveDir {
            get {
                if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "Data")) {
                    Directory.CreateDirectory(AppDomain.CurrentDomain.BaseDirectory + "Data");
                }
                return (AppDomain.CurrentDomain.BaseDirectory + "/Data");
            }
        }

        private List<string> files = new List<string>();
        private List<string> dbFiles = new List<string>();

        /// <summary>Define the name of the table.</summary>
        private readonly string tableName = "cve";
        #endregion

        public ConvertCveToDbController(List<string> files) {
            this.files = files; // cve files

            // initialize filelist
            Regex regexYear = new Regex(@"\\cves\\(\d{4})\\");
            Stack<DirectoryInfo> stack = new Stack<DirectoryInfo>();
            stack.Push(new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory + "raw"));

            while (stack.Count > 0) {
                DirectoryInfo currentDirectory = stack.Pop();
                string currentDirectoryPath = currentDirectory.FullName;


                Match match = regexYear.Match(currentDirectoryPath);
                if (match.Success) {
                    // Jahreszahl extrahieren
                    dbFiles.Add(match.Groups[1].Value);
                }

                DirectoryInfo[] subdirectory = currentDirectory.GetDirectories();
                foreach (DirectoryInfo subdirectoryInfo in subdirectory) {
                    stack.Push(subdirectoryInfo);
                }
            }

            dbFiles = dbFiles.Distinct().Order().ToList();
            dbFiles.ForEach(Console.WriteLine);
        }

        public bool ConvertRawCve() {
            try {
                foreach (string file in dbFiles) {
                    using (LiteDatabase db = new LiteDatabase(file)) {
                        ILiteCollection<CVEcomp> col = db.GetCollection<CVEcomp>(tableName);

                        CVEcomp cve = JsonConvert.DeserializeObject<CVEcomp>(File.ReadAllText(file))!;

                        col.Insert(cve.cveMetadata.cveId, cve);
                    }
                }
                return true;
            }
            catch {
                return false;
            }
        }
    }
}
