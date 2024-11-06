using System.Text.Json.Serialization;

namespace Modells {
    
    public class Report {

        /// <summary></summary>
        [JsonPropertyName(nameof(AnalysedRepoUuid))]
        public string AnalysedRepoUuid { get; set; } = "";

        /// <summary></summary>
        [JsonPropertyName(nameof(AnalysedRepoTag))]
        public string? AnalysedRepoTag { get; set; } = null;

        /// <summary></summary>
        [JsonPropertyName(nameof(AnalysedRepoTagDateTime))]
        public string? AnalysedRepoTagDateTime { get; set; } = null;

        /// <summary></summary>
        [JsonPropertyName(nameof(ReportMetrics))]
        public object ReportMetrics { get; set; } = new ReportMetric();
    }
}
