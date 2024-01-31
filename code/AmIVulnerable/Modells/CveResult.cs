namespace Modells {

    public class CveResult {

        public string CveNumber { get; set; } = "";
        public string Version { get; set; } = "";
        public string Designation { get; set; } = "";

        /// <summary>Empty ctor</summary>
        public CveResult() {
        }
    }
}
