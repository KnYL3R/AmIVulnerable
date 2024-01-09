using Microsoft.AspNetCore.Mvc;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class DbController : ControllerBase {

        [HttpGet]
        [Route("CheckRawDir")]
        public IActionResult IsRawDataThere() {
            string path = $"{AppDomain.CurrentDomain.BaseDirectory}raw";
            DirectoryInfo directoryInfo = new DirectoryInfo(path);
            if (directoryInfo.GetDirectories().Count() != 0) {
                return Ok();
            }
            else {
                return NoContent();
            }
        }

        [HttpGet]
        [Route("ConvertRawDirToDb")]
        public IActionResult ConvertRawFile() {
            return Ok();
        }
    }
}
