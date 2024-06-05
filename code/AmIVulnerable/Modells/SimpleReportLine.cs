namespace Modells {
    public class SimpleReportLine {
        public string ProjectUrl { get; set; }
        public string Tag { get; set; }
        public int TotalDirectDependencies { get; set; }
        public int TotalDirectAndTransitiveDependencies { get; set; }
        public int TotalDirectVulnerabilities { get; set; }
        public int TotalDirectAndTransitiveVulnerabilities { get; set; }
        public List<int> TransitiveVulnerabilitiesDepth { get; set; } = [];
        public int HighestDirectSeverity { get; set; }
        public int MyProperty { get; set; }
        public HighestTransitiveSeverity HighestTransitiveSeverity { get; set; } = new HighestTransitiveSeverity();
    }

    public class HighestTransitiveSeverity {
        public int TransitivityDegree { get; set; }
        public int Severity { get; set; }
    }
}
