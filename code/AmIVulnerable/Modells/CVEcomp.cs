namespace Modells {

    /// <summary>Root class for the CVE Data</summary>
    public class CVEcomp {
        /// <summary></summary>
        public string dataType { get; set; } = "";
        /// <summary></summary>
        public string dataVersion { get; set; } = "";
        /// <summary></summary>
        public CveMetadata cveMetadata { get; set; } = new CveMetadata();
        /// <summary></summary>
        public Containers containers { get; set; } = new Containers();
    }

    public class Affected {
        public string vendor { get; set; } = "";
        public string product { get; set; } = "";
        public List<string> platforms { get; set; } = [];
        public string collectionURL { get; set; } = "";
        public string packageName { get; set; } = "";
        public string repo { get; set; } = "";
        public List<string> modules { get; set; } = [];
        public List<string> programFiles { get; set; } = [];
        public List<ProgramRoutine> programRoutines { get; set; } = [];
        public List<Version> versions { get; set; } = [];
        public string defaultStatus { get; set; } = "";
    }

    public class Change {
        public string at { get; set; } = "";
        public string status { get; set; } = "";
    }

    public class Cna {
        public ProviderMetadata providerMetadata { get; set; }
        public string title { get; set; } = "";
        public DateTime datePublic { get; set; } = new DateTime();
        public List<ProblemType> problemTypes { get; set; } = [];
        public List<Impact> impacts { get; set; } = [];
        public List<Affected> affected { get; set; } = [];
        public List<Description> descriptions { get; set; } = [];
        public List<Metric> metrics { get; set; } = [];
        public List<Solution> solutions { get; set; } = [];
        public List<Workaround> workarounds { get; set; } = [];
        public List<Configuration> configurations { get; set; } = [];
        public List<Exploit> exploits { get; set; } = [];
        public List<Timeline> timeline { get; set; } = [];
        public List<Credit> credits { get; set; } = [];
        public List<Reference> references { get; set; } = [];
        public Source source { get; set; } = new Source();
        public List<TaxonomyMapping> taxonomyMappings { get; set; } = [];
    }

    public class Configuration {
        public string lang { get; set; } = "";
        public string value { get; set; } = "";
        public List<SupportingMedium> supportingMedia { get; set; } = [];
    }

    public class Containers {
        public Cna cna { get; set; } = new Cna();
    }

    public class Credit {
        public string lang { get; set; } = "";
        public string value { get; set; } = "";
        public string type { get; set; } = "";
    }

    public class CveMetadata {
        public string cveId { get; set; } = "";
        public string assignerOrgId { get; set; } = "";
        public string assignerShortName { get; set; } = "";
        public string requesterUserId { get; set; } = "";
        public int serial { get; set; } = -1;
        public string state { get; set; } = "";
    }

    public class CvssV31 {
        public string version { get; set; } = "";
        public string attackVector { get; set; } = "";
        public string attackComplexity { get; set; } = "";
        public string privilegesRequired { get; set; } = "";
        public string userInteraction { get; set; } = "";
        public string scope { get; set; } = "";
        public string confidentialityImpact { get; set; } = "";
        public string integrityImpact { get; set; } = "";
        public string availabilityImpact { get; set; } = "";
        public double baseScore { get; set; } = -1;
        public string baseSeverity { get; set; } = "";
        public string vectorString { get; set; } = "";
    }

    public class Description {
        public string lang { get; set; } = "";
        public string cweId { get; set; } = "";
        public string description { get; set; } = "";
        public string type { get; set; } = "";
        public string value { get; set; } = "";
        public List<SupportingMedium> supportingMedia { get; set; } = [];
    }

    public class Exploit {
        public string lang { get; set; } = "";
        public string value { get; set; } = "";
        public List<SupportingMedium> supportingMedia { get; set; } = [];
    }

    public class Impact {
        public string capecId { get; set; } = "";
        public List<Description> descriptions { get; set; } = [];
    }

    public class Metric {
        public string format { get; set; } = "";
        public List<Scenario> scenarios { get; set; } = [];
        public CvssV31 cvssV3_1 { get; set; } = new CvssV31();
    }

    public class ProblemType {
        public List<Description> descriptions { get; set; } = [];
    }

    public class ProgramRoutine {
        public string name { get; set; } = "";
    }

    public class ProviderMetadata {
        public string orgId { get; set; } = "";
        public string shortName { get; set; } = "";
        public DateTime dateUpdated { get; set; } = new DateTime();
    }

    public class Reference {
        public string url { get; set; } = "";
        public string name { get; set; } = "";
        public List<string> tags { get; set; } = [];
    }

    public class Scenario {
        public string lang { get; set; } = "";
        public string value { get; set; } = "";
    }

    public class Solution {
        public string lang { get; set; } = "";
        public string value { get; set; } = "";
        public List<SupportingMedium> supportingMedia { get; set; } = [];
    }

    public class Source {
        public List<string> defects { get; set; } = [];
        public string advisory { get; set; } = "";
        public string discovery { get; set; } = "";
    }

    public class SupportingMedium {
        public string type { get; set; } = "";
        public bool? base64 { get; set; } = null;
        public string value { get; set; } = "";
    }

    public class TaxonomyMapping {
        public string taxonomyName { get; set; } = "";
        public string taxonomyVersion { get; set; } = "";
        public List<TaxonomyRelation> taxonomyRelations { get; set; } = [];
    }

    public class TaxonomyRelation {
        public string taxonomyId { get; set; } = "";
        public string relationshipName { get; set; } = "";
        public string relationshipValue { get; set; } = "";
    }

    public class Timeline {
        public DateTime time { get; set; } = new DateTime();
        public string lang { get; set; } = "";
        public string value { get; set; } = "";
    }

    public class Version {
        public string version { get; set; } = "";
        public string status { get; set; } = "";
        public string lessThan { get; set; } = "";
        public string versionType { get; set; } = "";
        public List<Change> changes { get; set; } = [];
    }

    public class Workaround {
        public string lang { get; set; } = "";
        public string value { get; set; } = "";
        public List<SupportingMedium> supportingMedia { get; set; } = [];
    }
}
