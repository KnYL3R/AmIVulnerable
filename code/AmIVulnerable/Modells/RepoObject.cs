using System.Text.Json.Serialization;

namespace Modells {

    /// <summary></summary>
    public class RepoObject {

        /// <summary></summary>
        [JsonPropertyName(nameof(RepoUrl))] 
        public string RepoUrl { get; set; } = "";

        /// <summary>by null no tag specified -> use latest commit</summary>
        [JsonPropertyName(nameof(RepoTag))]
        public string? RepoTag { get; set; } = null;

    }
}
