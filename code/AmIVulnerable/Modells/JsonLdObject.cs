using System.Text.Json.Serialization;

namespace Modells {
    
    public class JsonLdObject {
    
        [JsonPropertyName("@context")]
        public string Context { get; set; } = "";
        public object Data { get; set; } = new object();
    }
}
