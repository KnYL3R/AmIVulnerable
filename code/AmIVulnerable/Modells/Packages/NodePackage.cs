namespace Modells.Packages {

    public class NodePackage {

        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public List<NodePackage> Dependencies { get; set; } = [];
        public Description Description { get; set; } = new Description();
        public CvssV31 CvssV31 { get; set; } = new CvssV31();

        /// <summary>Empty ctor</summary>
        public NodePackage() {
        }
    }
}