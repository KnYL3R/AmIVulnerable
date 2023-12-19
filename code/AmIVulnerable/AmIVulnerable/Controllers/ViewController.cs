using Microsoft.AspNetCore.Mvc;

namespace AmIVulnerable.Controllers {

    [Route("views")]
    [Controller]
    public class ViewController : Controller {

        [HttpGet]
        [Route("json-ld")]
        public IActionResult JsonLd () {
            string path = Path.Combine(Directory.GetCurrentDirectory() + @"\Controllers\Views", "json-ld.html");

            return Content(System.IO.File.ReadAllText(path), "text/html");
        }
    }
}
