using LiteDb.Controller;
using Microsoft.AspNetCore.Mvc;

namespace AmIVulnerable.Controllers {

    /// <summary>
    /// Controller, that interact with the test database.
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class DbTest : ControllerBase {

        [HttpGet]
        [Route("ping")]
        public IActionResult Ping() {
            return Ok();
        }

        [HttpGet]
        [Route("FillSampleDatabase")]
        public IActionResult SimplePing() {
            ReachTestDbController dbConnection = new ReachTestDbController();
            dbConnection.CreateSampleData();
            return Ok();
        }

        [HttpGet]
        [Route("RequestSample")]
        public IActionResult RequestSample() {
            ReachTestDbController dbConnection = new ReachTestDbController();
            string res = dbConnection.ReadSampleData();
            if (res is "") {
                return Ok();
            }
            else {
                return BadRequest(res);
            }
        }

        [HttpDelete]
        [Route("deleteSample")]
        public IActionResult Delete() {
            ReachTestDbController dbConnection = new ReachTestDbController();
            int res = dbConnection.ResetSampleDatabase();
            if (res == 0) {
                return NoContent();
            }
            else if (res == 4) {
                return Ok();
            }
            else {
                return BadRequest(res);
            }
        }
    }
}
