using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Modells {
    public class ProjectMetricResult {
        [JsonProperty("ProjectUrl")]
        [JsonPropertyName("ProjectUrl")]
        public string ProjectUrl { get; set; } = "";
        [JsonProperty("AnalyseTime")]
        [JsonPropertyName("AnalyseTime")]
        public DateTime AnalyseTime { get; set; } = new DateTime();
        [JsonProperty("VulnerabilityMetrics")]
        [JsonPropertyName("VulnerabilityMetrics")]
        public List<VulnerabilityMetric> VulnerabilityMetrics { get; set; } = new List<VulnerabilityMetric>();

    }
    public class VulnerabilityMetric {
        [JsonProperty("PackageName")]
        [JsonPropertyName("PackageName")]
        public string PackageName { get; set; } = "";
        [JsonProperty("PackageVersion")]
        [JsonPropertyName("PackageVersion")]
        public string PackageVersion { get; set; } = "";
        [JsonProperty("CvssVersion")]
        [JsonPropertyName("CvssVersion")]
        public List<string> CvssVersion { get; set; } = new List<string>();
        [JsonProperty("NistSeverity")]
        [JsonPropertyName("NistSeverity")]
        public List<double> NistSeverity { get; set; } = new List<double>();
        [JsonProperty("MetricScore")]
        [JsonPropertyName("MetricScore")]
        public double MetricScore { get; set; }
        [JsonProperty("MetricData")]
        [JsonPropertyName("MetricData")]
        public List<MetricData> MetricData { get; set; } = new List<MetricData>();
    }
    public class MetricData {
        [JsonProperty("TransitiveDepths")]
        [JsonPropertyName("TransitiveDepths")]
        public List<int> TransitiveDepths { get; set; } = new List<int>();
        [JsonProperty("Vector")]
        [JsonPropertyName("Vector")]
        public Vector Vector { get; set; } = new Vector();
        [JsonProperty("UsageCount")]
        [JsonPropertyName("UsageCount")]
        public int UsageCount { get; set; }
        [JsonProperty("OwnDependenciesCount")]
        [JsonPropertyName("OwnDependenciesCount")]
        public int OwnDependenciesCount { get; set; }
        [JsonProperty("OwnVulnerabilitiesCount")]
        [JsonPropertyName("OwnVulnerabilitiesCount")]
        public int OwnUniqueVulnerabilitiesCount { get; set; }
        [JsonProperty("PublishedSince")]
        [JsonPropertyName("PublishedSince")]
        public DateTime PublishedSince { get; set; }
    }
    public class Vector {
        [JsonProperty("AttackVector")]
        [JsonPropertyName("AttackVector")]
        public AttackVector AttackVector {  get; set; } = new AttackVector();
        [JsonProperty("AttackComplexity")]
        [JsonPropertyName("AttackComplexity")]
        public AttackComplexity AttackComplexity { get; set; } = new AttackComplexity();
        [JsonProperty("PrivilegesRequired")]
        [JsonPropertyName("PrivilegesRequired")]
        public BaseScoreMetric PrivilegesRequired { get; set; } = new BaseScoreMetric();
        [JsonProperty("UserInteraction")]
        [JsonPropertyName("UserInteraction")]
        public UserInteraction UserInteraction { get; set; } = new UserInteraction();
        [JsonProperty("Scope")]
        [JsonPropertyName("Scope")]
        public Scope Scope { get; set; } = new Scope();
        [JsonProperty("ConfidentialityImpact")]
        [JsonPropertyName("ConfidentialityImpact")]
        public BaseScoreMetric ConfidentialityImpact { get; set; } = new BaseScoreMetric();
        [JsonProperty("IntegrityImpact")]
        [JsonPropertyName("IntegrityImpact")]
        public BaseScoreMetric IntegrityImpact { get; set; } = new BaseScoreMetric();
        [JsonProperty("AvailabilityImpact")]
        [JsonPropertyName("AvailabilityImpact")]
        public BaseScoreMetric AvailabilityImpact { get; set; } = new BaseScoreMetric();
    }
    public enum AttackVector {
        Network,
        Adjacent_Network,
        Local,
        Physial,
        Not_Available,
    }
    public enum AttackComplexity {
        Low,
        High,
        Not_Available,
    }
    public enum UserInteraction {
        None,
        Required,
        Not_Available,
    }
    public enum Scope {
        Unchanged,
        Changed,
        Not_Available,
    }
    public enum BaseScoreMetric {
        None,
        Low,
        High,
        Not_Available,
    }
}
