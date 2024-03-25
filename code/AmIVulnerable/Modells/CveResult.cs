namespace Modells {

    public class CveResult {

        public string CveNumber { get; set; } = "";
        public string Version { get; set; } = "";
        public string Designation { get; set; } = "";
        public Description Description { get; set; } = new Description();
        public CvssV31 CvssV31 { get; set; } = new CvssV31();

        /// <summary>Empty ctor</summary>
        public CveResult() {
        }
    }
}
