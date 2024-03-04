using Microsoft.AspNetCore.Mvc;

namespace AmIVulnerable.Controllers {

    [Route("views")]
    [Controller]
    public class ViewController : Controller {
        [HttpGet]
        [Route("cveResult")]
        public IActionResult CveResultLdGet() {
            string path = Path.Combine(Directory.GetCurrentDirectory() + @"\Controllers\Views", "cveResult-ld.html");

            return Content(System.IO.File.ReadAllText(path), "text/html");
        }

        [HttpGet]
        [Route("nodePackageResult")]
        public IActionResult NodePackageResultLdGet() {
            string path = Path.Combine(Directory.GetCurrentDirectory() + @"\Controllers\Views", "nodePackageResult-ld.html");

            return Content(System.IO.File.ReadAllText(path), "text/html");
        }
    }
}
