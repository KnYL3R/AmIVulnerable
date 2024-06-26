using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Modells {
    public class TimeSlice {
        public string TagName { get; set; } = "No tag or latest!";
        public DateTime Timestamp { get; set; }
        public int CountDirectDependencies { get; set; }
        public int CountTransitiveDependencies { get; set; }
        public int CountUniqueTransitiveDependencies { get; set; }
        public int CountKnownDirectVulnerabilities { get; set; }
        public int CountKnownTransitiveVulnerabilities { get; set; }
        public int CountKnownUniqueTransitiveVulnerabilities { get; set; }
        public int CountToDateDirectVulnerabilities { get; set; }
        public int CountToDateTransitiveVulnerabilities { get; set; }
        public int CountToDateUniqueTransitiveVulnerabilities { get; set; }
        public int CountTotalFoundVulnerabilities { get; set; }
    }
}
