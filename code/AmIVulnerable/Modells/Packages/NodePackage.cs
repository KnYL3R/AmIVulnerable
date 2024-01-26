namespace Modells.Packages {

    public class NodePackage {

        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public List<NodePackage> Dependencies { get; set; } = [];

        public NodePackage() {
        }
    }
}