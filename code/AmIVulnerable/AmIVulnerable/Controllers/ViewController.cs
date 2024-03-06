using Microsoft.AspNetCore.Mvc;

namespace AmIVulnerable.Controllers {

    [Route("views")]
    [Controller]
    public class ViewController : Controller {

        /// <summary>
        /// API-Get request to show json-ld data.
        /// </summary>
        /// <returns>Json-ld data as html</returns>
        [HttpGet]
        [Route("json-ld")]
        public IActionResult JsonLd () {
            string path = Path.Combine(Directory.GetCurrentDirectory() + @"\Controllers\Views", "json-ld.html");

            return Content(System.IO.File.ReadAllText(path), "text/html");
        }
    }
}
