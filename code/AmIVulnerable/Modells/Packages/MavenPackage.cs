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
        public List<MavenPackage> children { get; set; }
        
        /// <summary>
        /// Converts MavenPackage to Package
        /// </summary>
        /// <returns></returns>
        public Package ToPackage() {
            Package package = new Package();
            package.Name = groupId + ":" + artifactId;
            package.Version = version;
            //Own Dependencies???!?!?!?
            package.Dependencies = GetChildren(children);

            return package;
        }

        private List<Package> GetChildren(List<MavenPackage> mavenDependencies) {
            List<Package> dependencies = new List<Package>();
            foreach (MavenPackage mavenDependency in mavenDependencies) {
                dependencies.Add(mavenDependency.ToPackage());
            }
            return dependencies;
        }
    }
}
