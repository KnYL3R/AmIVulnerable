using Newtonsoft.Json;
using System.Text.Json.Serialization;

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
        public AttackVector AttackVector { get; set; } = AttackVector.Not_Available;
        [JsonProperty("AttackComplexity")]
        [JsonPropertyName("AttackComplexity")]
        public AttackComplexity AttackComplexity { get; set; } = AttackComplexity.Not_Available;
        [JsonProperty("PrivilegesRequired")]
        [JsonPropertyName("PrivilegesRequired")]
        public PrivilegesRequired PrivilegesRequired { get; set; } = PrivilegesRequired.Not_Available;
        [JsonProperty("UserInteraction")]
        [JsonPropertyName("UserInteraction")]
        public UserInteraction UserInteraction { get; set; } = UserInteraction.Not_Available;
        [JsonProperty("Scope")]
        [JsonPropertyName("Scope")]
        public Scope Scope { get; set; } = Scope.Not_Available;
        [JsonProperty("ConfidentialityImpact")]
        [JsonPropertyName("ConfidentialityImpact")]
        public BaseScoreMetric ConfidentialityImpact { get; set; } = BaseScoreMetric.Not_Available;
        [JsonProperty("IntegrityImpact")]
        [JsonPropertyName("IntegrityImpact")]
        public BaseScoreMetric IntegrityImpact { get; set; } = BaseScoreMetric.Not_Available;
        [JsonProperty("AvailabilityImpact")]
        [JsonPropertyName("AvailabilityImpact")]
        public BaseScoreMetric AvailabilityImpact { get; set; } = BaseScoreMetric.Not_Available;
        public decimal BaseScore() {
            decimal baseScore = -1;
            //If any Vector property not set return -1
            if (AttackVector == AttackVector.Not_Available ||
                AttackComplexity == AttackComplexity.Not_Available ||
                PrivilegesRequired == PrivilegesRequired.Not_Available ||
                UserInteraction == UserInteraction.Not_Available ||
                Scope == Scope.Not_Available ||
                ConfidentialityImpact == BaseScoreMetric.Not_Available ||
                IntegrityImpact == BaseScoreMetric.Not_Available ||
                AvailabilityImpact == BaseScoreMetric.Not_Available) {
                return baseScore;
            }

            //Impact Base Score
            decimal ISC_Base = 1 - (
                (1 - ((decimal)ConfidentialityImpact / 100)) *
                (1 - ((decimal)IntegrityImpact / 100)) *
                (1 - ((decimal)AvailabilityImpact / 100))
                );

            //Impact Score
            decimal ISC = 0;
            if (Scope == Scope.Unchanged) {
                ISC = 6.42m * ISC_Base;
            }
            else if (Scope == Scope.Changed) {
                ISC = 7.52m * (ISC_Base - 0.029m) - 3.25m * (decimal)Math.Pow(((double)ISC_Base - 0.02), 15.0);
            }

            //BaseScore
            if (ISC == 0) {
                baseScore = 0;
            }
            else if (Scope == Scope.Unchanged) {//Exploitability Score
                decimal ESC = 8.22m *
                    ((decimal)AttackVector / 100) *
                    ((decimal)AttackComplexity / 100) *
                    ((decimal)PrivilegesRequired / 100) *
                    ((decimal)UserInteraction / 100);
                baseScore = Math.Round(Math.Min((ISC + ESC), 10), 1);
            }
            else if (Scope == Scope.Changed) {//Exploitability Score
                if (PrivilegesRequired == PrivilegesRequired.High) PrivilegesRequired = PrivilegesRequired.High_Scope_Changed;
                if (PrivilegesRequired == PrivilegesRequired.Low) PrivilegesRequired = PrivilegesRequired.Low_Scope_Changed;
                decimal ESC = 8.22m *
                    ((decimal)AttackVector / 100) *
                    ((decimal)AttackComplexity / 100) *
                    ((decimal)PrivilegesRequired / 100) *
                    ((decimal)UserInteraction / 100);
                baseScore = Math.Round(Math.Min(1.08m * (ISC + ESC), 10), 1);
            }
            return baseScore;
        }
    }
    public enum AttackVector {
        Network = 85,
        Adjacent_Network = 62,
        Local = 55,
        Physial = 20,
        Not_Available = -1,
    }
    public enum AttackComplexity {
        Low = 77,
        High = 44,
        Not_Available = -1,
    }
    public enum UserInteraction {
        None = 85,
        Required = 62,
        Not_Available = -1,
    }
    public enum Scope {
        Unchanged,
        Changed,
        Not_Available = -1,
    }
    //higher if scope is changed
    public enum PrivilegesRequired {
        None = 85,
        Low = 62,
        High = 27,
        Low_Scope_Changed = 68,
        High_Scope_Changed = 50,
        Not_Available = -1,
    }
    public enum BaseScoreMetric {
        None = 0,
        Low = 22,
        High = 56,
        Not_Available = -1,
    }
}