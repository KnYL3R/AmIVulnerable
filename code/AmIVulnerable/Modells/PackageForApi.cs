using System.Text.Json.Serialization;

namespace Modells {

    public class PackageForApi {

        [JsonPropertyName(nameof(PackageName))]
        public string PackageName { get; set; } = "";

        [JsonPropertyName(nameof(PackageVersion))]
        public string PackageVersion { get; set; } = "";

        public override string ToString() {
            return $"{PackageName} | {PackageVersion}";
        }
    }
}
