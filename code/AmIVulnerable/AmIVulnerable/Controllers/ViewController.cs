using Microsoft.AspNetCore.Mvc;

namespace AmIVulnerable.Controllers {

    [Route("views")]
    [Controller]
    public class ViewController : Controller {
        
        [HttpGet]
        [Route("cveResult")]
        public IActionResult CveResultLdGet() {
            if (!(this.Request.Headers.Accept.Equals("text/html") || this.Request.Headers.Accept.Equals("*/*"))) {
                return StatusCode(406);
            }
            string path = Path.Combine(Directory.GetCurrentDirectory() + @"/Controllers/Views", "cveResult-ld.html");

            return Content(System.IO.File.ReadAllText(path), "text/html");
        }

        /// <summary>
        /// API-Get request to show json-ld data.
        /// </summary>
        /// <returns>Json-ld data as html</returns>
        [HttpGet]
        [Route("nodePackageResult")]
        public IActionResult NodePackageResultLdGet() {
            if (!(this.Request.Headers.Accept.Equals("text/html") || this.Request.Headers.Accept.Equals("*/*"))) {
                return StatusCode(406);
            }
            string path = Path.Combine(Directory.GetCurrentDirectory() + @"/Controllers/Views", "nodePackageResult-ld.html");

            return Content(System.IO.File.ReadAllText(path), "text/html");
        }
    }
}
