using Newtonsoft.Json;
using System.Text.Json.Serialization;

namespace Modells.Yarn {
    internal class YarnTree {
        [JsonProperty("type")]
        [JsonPropertyName("type")]
        public string type { get; set; }

        [JsonProperty("data")]
        [JsonPropertyName("data")]
        public Data data { get; set; }
    }

    public class Child {
        [JsonProperty("name")]
        [JsonPropertyName("name")]
        public string name { get; set; }
        public string version { get; set; } = string.Empty;

        [JsonProperty("color")]
        [JsonPropertyName("color")]
        public string color { get; set; }

        [JsonProperty("shadow")]
        [JsonPropertyName("shadow")]
        public bool shadow { get; set; }

        [JsonProperty("children")]
        [JsonPropertyName("children")]
        public List<Child> children { get; set; }

        [JsonProperty("hint")]
        [JsonPropertyName("hint")]
        public object hint { get; set; }

        [JsonProperty("depth")]
        [JsonPropertyName("depth")]
        public int? depth { get; set; }
    }

    public class Data {
        [JsonProperty("type")]
        [JsonPropertyName("type")]
        public string type { get; set; }

        [JsonProperty("trees")]
        [JsonPropertyName("trees")]
        public List<Child> children { get; set; }
    }
}
