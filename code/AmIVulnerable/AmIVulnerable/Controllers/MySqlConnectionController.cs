using Microsoft.AspNetCore.Mvc;
using MySql.Data.MySqlClient;
using SerilogTimings;
using System.Data;

namespace AmIVulnerable.Controllers {

    [Route("api/[controller]")]
    [ApiController]
    public class MySqlConnectionController : ControllerBase {

        private readonly IConfiguration Configuration;

        public MySqlConnectionController(IConfiguration configuration) {
            Configuration = configuration;
        }

        [HttpGet, Route("checkReachable")]
        public IActionResult PingWithDb() {
            using (Operation.Time("TaskDuration")) {
                try {
                    MySqlConnection c = new MySqlConnection(Configuration["ConnectionStrings:cvedb"]);

                    MySqlCommand cmd = new MySqlCommand("SELECT cve_number, designation FROM cve.cve", c);

                    c.Open();
                    MySqlDataReader reader = cmd.ExecuteReader();
                    DataTable dataTable = new DataTable();
                    dataTable.Load(reader);
                    reader.Close();
                    c.Close();

                    string r = "";
                    foreach (DataRow row in dataTable.Rows) {
                        foreach (object? item in row.ItemArray) {
                            r += item;
                        }
                    }

                    return Ok(r);
                }
                catch (Exception ex) {
                    return BadRequest(ex.ToString());
                }
            }
        }
    }
}
