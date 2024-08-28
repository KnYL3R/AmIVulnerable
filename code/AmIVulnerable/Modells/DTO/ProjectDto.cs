using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Modells.DTO {
    public class ProjectDto {
        public string ProjectUrl { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = [];
    }
}
