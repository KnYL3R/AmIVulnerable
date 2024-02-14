namespace Modells.Packages {
    public class NodePackageResult {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public bool isCveTracked { get; set; } = false;
        public List<NodePackageResult> Dependencies { get; set; } = [];

        /// <summary>Empty ctor</summary>
        public NodePackageResult() {
        }
    }
}
