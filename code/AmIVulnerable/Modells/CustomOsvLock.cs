namespace Modells {
    public class CustomOsvLock {
        public List<CustomResult> results = [];
    }
    public class CustomResult {
        public List<CustomPackageWrapper> packages = [];
        public CustomResult(List<CustomPackage> _packages) {
            List<CustomPackageWrapper> customPackageWrappers = new List<CustomPackageWrapper>();
            foreach(CustomPackage _package in _packages) {
                customPackageWrappers.Add(new CustomPackageWrapper(_package));
            }
            packages = customPackageWrappers;
        }
    }
    public class CustomPackageWrapper {
        public CustomPackageWrapper(CustomPackage _package) {
            package = _package;
        }
        public CustomPackage package;
    }
    public class CustomPackage {
        public CustomPackage(string _name, string _version, string _ecosystem) {
            name = _name;
            version = _version;
            ecosystem = _ecosystem;
        }
        public string name { get; set; }
        public string version { get; set; }
        public string ecosystem { get; set; }
    }
}
