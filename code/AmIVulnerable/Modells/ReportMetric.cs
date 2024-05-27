using System.Text.Json.Serialization;

namespace Modells {
    
    public class ReportMetric {

        /// <summary></summary>
        [JsonPropertyName(nameof(TotalDirectVulnerabilities))]
        public int TotalDirectVulnerabilities { get; set; } = new int();

        /// <summary></summary>
        [JsonPropertyName(nameof(TotalTransitiveVulnerabilities))]
        public int TotalTransitiveVulnerabilities { get; set; } = new int();

        /// <summary></summary>
        [JsonPropertyName(nameof(MeanSeverityDirectVulnerabilities))]
        public int MeanSeverityDirectVulnerabilities { get; set; } = new int();

        /// <summary></summary>
        [JsonPropertyName(nameof(MeanSeverityTransitiveVulnerabilities))]
        public int MeanSeverityTransitiveVulnerabilities { get; set; } = new int();
    }
}
