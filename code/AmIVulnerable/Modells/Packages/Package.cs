using System.Text.Json.Serialization;

namespace Modells.Packages {

    public class Package {
        public string Name { get; set; } = "";

        [JsonIgnore, Newtonsoft.Json.JsonIgnore]
        public string Version { get; set; } = "";
        public List<Package> Dependencies { get; set; } = [];

        [JsonIgnore, Newtonsoft.Json.JsonIgnore]
        public Description Description { get; set; } = new Description();

        [JsonIgnore, Newtonsoft.Json.JsonIgnore]
        public CvssV31 CvssV31 { get; set; } = new CvssV31();

        /// <summary>Empty ctor</summary>
        public Package() {
        }
    }
}