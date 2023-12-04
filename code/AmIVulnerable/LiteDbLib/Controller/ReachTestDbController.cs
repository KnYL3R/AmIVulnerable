using LiteDB;
using Modells;
using System.Configuration;

namespace LiteDb.Controller {

    /// <summary></summary>
    public class ReachTestDbController {

        /// <summary>Constructor, that test, if the Databasefile exist an create it, when not.</summary>
        public ReachTestDbController() {
            var temp = ConfigurationManager.AppSettings["PathToTestDb"]!;
            if (!File.Exists(temp)) {
                if (!Directory.Exists(temp[0..temp.LastIndexOf("/")])) {
                    Directory.CreateDirectory(temp[0..temp.LastIndexOf("/")]);
                }
                File.Create(temp).Close();
            }
        }

        /// <summary></summary>
        /// <returns></returns>
        public bool CreateSampleData() {
            using (var db = new LiteDatabase(ConfigurationManager.AppSettings["PathToTestDb"])) {
                var col = db.GetCollection<TestIdValueObject>("Testzahlen");
                if (col.Count() == 0) {
                    col.Insert(new TestIdValueObject() { Id = col.Count() + 1, Value = 0 });
                    //col.EnsureIndex(x => x.Id);
                    col.Insert(new TestIdValueObject() { Id = col.Count() + 1, Value = 1 });
                    //col.EnsureIndex(x => x.Id);
                    col.Insert(new TestIdValueObject() { Id = col.Count() + 1, Value = 2 });
                    //col.EnsureIndex(x => x.Id);
                    col.Insert(new TestIdValueObject() { Id = col.Count() + 1, Value = 3 });
                    //col.EnsureIndex(x => x.Id);
                }
                return true;
            }
        }

        /// <summary></summary>
        /// <returns></returns>
        public int ResetSampleDatabase() {
            using (var db = new LiteDatabase(ConfigurationManager.AppSettings["PathToTestDb"])) {
                var col = db.GetCollection<TestIdValueObject>("Testzahlen");
                return col.DeleteAll();
            }
        }

        /// <summary></summary>
        /// <returns></returns>
        public string ReadSampleData() {
            try {
                using (var db = new LiteDatabase(ConfigurationManager.AppSettings["PathToTestDb"])) {
                    var col = db.GetCollection<TestIdValueObject>("Testzahlen");
                    List<TestIdValueObject> list = col.FindAll().ToList();
                    if ((list[0].Value == 0) && (list[1].Value == 1) &&
                        (list[2].Value == 2) && (list[3].Value == 3)) {
                        return "";
                    }
                    else {
                        return "Wrong Dataset!";
                    }
                }
            }
            catch (Exception ex) {
                return ex.Message;
            }            
        }
    }
}
