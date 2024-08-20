using System.Diagnostics;
using F = System.IO.File;

namespace Modells {
    public class Project {
        public string ProjectUrl { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = [];

        private string dirGuid = "";
        private readonly static string CLI = "cmd";
        private readonly string CLI_RM = CLI == "cmd" ? "del" : "rm";

        public Project() { }

        public async Task<string> Clone() {
            if (ProjectUrl is null) {
                this.dirGuid = "Err";
                return "Err";
            }

            else { // clone the repo
                Guid repoId = Guid.NewGuid();
                string trimmedUrl = ProjectUrl[(ProjectUrl.IndexOf("//") + 2)..(ProjectUrl.Length)];
                trimmedUrl = trimmedUrl[(trimmedUrl.IndexOf('/') + 1)..(trimmedUrl.Length)];
                string owner = trimmedUrl[0..trimmedUrl.IndexOf('/', 1)];
                string designation = trimmedUrl[(owner.Length + 1)..trimmedUrl.Length];
                if (designation.Contains('/')) {
                    designation = designation[0..trimmedUrl.IndexOf('/', owner.Length + 1)];
                }

                await Clone(ProjectUrl, repoId.ToString());
                this.dirGuid = repoId.ToString();
                return repoId.ToString();
            }
        }
        private static async Task Clone(string url, string dir) {
            try {
                await Task.Run(() => {
                    if (Directory.Exists(dir)) {
                        RemoveReadOnlyAttribute(dir);
                        Directory.Delete(dir, true);
                    }
                    Process.Start("git", $"clone {url} {AppDomain.CurrentDomain.BaseDirectory + dir}").WaitForExit();
                });
            }
            catch (Exception ex) {
                await Console.Out.WriteLineAsync(ex.StackTrace);
            }
        }
        private static void RemoveReadOnlyAttribute(string path) {
            DirectoryInfo directoryInfo = new DirectoryInfo(path);

            foreach (FileInfo file in directoryInfo.GetFiles()) {
                file.Attributes &= ~FileAttributes.ReadOnly;
            }

            foreach (DirectoryInfo subDirectory in directoryInfo.GetDirectories()) {
                RemoveReadOnlyAttribute(subDirectory.FullName);
            }
        }
        public void Install() {
            ExecuteCommand(CLI_RM, ".npmrc", dirGuid);
            ExecuteCommand("npm", "install", dirGuid);
            ExecuteCommand("npm", "i --lockfile-version 3 --package-lock-only", dirGuid);
            return;
        }

        /// <summary>
        /// Starts a process that runs a command.
        /// </summary>
        /// <param name="prog">Programm used for commands</param>
        /// <param name="command">Command used for programm</param>
        private void ExecuteCommand(string prog, string command, string dir) {
            ProcessStartInfo process = new ProcessStartInfo {
                FileName = CLI,
                RedirectStandardInput = true,
                WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory + dir,
            };
            Process runProcess = Process.Start(process)!;
            runProcess.StandardInput.WriteLine($"{prog} {command}");
            runProcess.StandardInput.WriteLine($"exit");
            runProcess.WaitForExit();
        }
    }
}