namespace Modells {
    public class SimpleReportLine {
        public string ProjectUrl { get; set; }
        public string Tag { get; set; }
        public int TotalReleaseDirectDependencies { get; set; }
        public int TotalReleaseDirectAndTransitiveDependencies { get; set; }
        public int TotalReleaseDirectVulnerabilities { get; set; }
        public int TotalReleaseDirectAndTransitiveVulnerabilities { get; set; }
        public List<int> releaseVulnerabilitiesDepth { get; set; } = [];
        public double releaseHighestDirectScore { get; set; }
        public string releaseHighestDirectSeverity { get; set; }
        public double releaseHighestTransitiveScore { get; set; }
        public DateTime releaseDateTime { get; set; }
        public int TotalCurrentDirectDependencies { get; set; }
        public int TotalCurrentDirectAndTransitiveDependencies { get; set; }
        public int TotalCurrentDirectVulnerabilities { get; set; }
        public int TotalCurrentDirectAndTransitiveVulnerabilities { get; set; }
        public double currentHighestDirectScore { get; set; }
        public string currentHighestDirectSeverity { get; set; }
        public double currentHighestTransitiveScore { get; set; }
    }
}
