using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Modells.Packages {
    public class MavenPackage {
        public string groupId { get; set; }
        //Package name
        public string artifactId { get; set; }
        //Package version
        public string version { get; set; }
        public string type { get; set; }
        public string scope { get; set; }
        public string classifier { get; set; }
        public string optional { get; set; }
        //Own Dependencies
        public MavenPackage[] children { get; set; }
        
        /// <summary>
        /// Converts MavenPackage to Package
        /// </summary>
        /// <returns></returns>
        public Package ToPackage() {
            Package package = new Package();
            package.Name = artifactId;
            package.Version = version;
            //Own Dependencies???!?!?!?

            return null;
        }
    }
}
