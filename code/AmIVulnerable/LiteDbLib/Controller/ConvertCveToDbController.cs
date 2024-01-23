using LiteDB;
using Modells;
using Newtonsoft.Json;
using System.Text.RegularExpressions;

namespace LiteDbLib.Controller {

    public class ConvertCveToDbController {

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

        private List<string> files = new List<string>();
        private List<string> dbFiles = new List<string>();

        /// <summary>Define the name of the table.</summary>
        private readonly string tableName = "cve";

        /// <summary>Find the Year of the CVE-File</summary>
        Regex regexYear = new Regex(@"\\cves\\(\d{4})\\");
        #endregion

        public ConvertCveToDbController(List<string> files) {
            this.files = files; // cve files

            // initialize directorylist
            Stack<DirectoryInfo> stack = new Stack<DirectoryInfo>();
            stack.Push(new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory + "raw"));

            while (stack.Count > 0) {
                DirectoryInfo currentDirectory = stack.Pop();
                string currentDirectoryPath = currentDirectory.FullName;


                Match match = regexYear.Match(currentDirectoryPath);
                if (match.Success) {
                    if (!dbFiles.Contains(match.Groups[1].Value)) { // only add when not already in list
                        dbFiles.Add(match.Groups[1].Value);
                    }
                }

                DirectoryInfo[] subdirectory = currentDirectory.GetDirectories();
                foreach (DirectoryInfo subdirectoryInfo in subdirectory) {
                    stack.Push(subdirectoryInfo);
                }
            }

            dbFiles = dbFiles.Order().ToList(); //.Distinct() because of line 45 not neccessary
        }

        public bool ConvertRawCve()
        {
            try
            {
                foreach (string file in files)
                {
                    Console.WriteLine(file);
                    Match match = regexYear.Match(file);
                    int dbFile = dbFiles.FindIndex(x => x.Equals(match.Groups[1].Value));
                    if (dbFile == -1)
                    {
                        continue; // if year was not found, continue convert and ignore file
                    }
                    using (LiteDatabase db = new LiteDatabase($"{saveDir}\\{dbFiles[dbFile]}.litedb"))
                    {
                        ILiteCollection<CVEcomp> col = db.GetCollection<CVEcomp>(tableName);

                        CVEcomp cve = JsonConvert.DeserializeObject<CVEcomp>(File.ReadAllText(file))!;

                        col.Insert(cve.cveMetadata.cveId, cve);
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
