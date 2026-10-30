using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Xml;

namespace SentinelTwo
{
    internal sealed class TaskDefinition
    {
        public string Description;
        public bool BootTrigger;          // true: BootTrigger; false: LogonTrigger for TriggerSid
        public string TriggerSid;
        public string PrincipalSid;
        public string LogonType;          // InteractiveToken or ServiceAccount
        public string Command;
        public string Arguments;
        public string ExecutionTimeLimit; // e.g. PT0S (no limit)
        public int RestartCount;          // 0 disables restart-on-failure
    }

    // Scheduled task management through schtasks.exe (registration, run, end, delete) and
    // the Task Scheduler COM service (running-state query, which is locale independent).
    internal static class Tasks
    {
        public static bool Exists(string name)
        {
            string output;
            return Exec("/Query /TN \"" + name + "\"", out output) == 0;
        }

        public static void Register(string name, TaskDefinition definition)
        {
            string xmlPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".xml");
            try
            {
                WriteXml(xmlPath, definition);
                string output;
                int code = Exec("/Create /TN \"" + name + "\" /XML \"" + xmlPath + "\" /F", out output);
                if (code != 0) throw new InvalidOperationException("schtasks /Create failed for " + name + ": " + output);
            }
            finally
            {
                if (File.Exists(xmlPath)) File.Delete(xmlPath);
            }
        }

        public static void Run(string name)
        {
            string output;
            if (Exec("/Run /TN \"" + name + "\"", out output) != 0)
                throw new InvalidOperationException("Could not start task " + name + ": " + output);
        }

        public static void End(string name)
        {
            string output;
            Exec("/End /TN \"" + name + "\"", out output);
        }

        public static void SetEnabled(string name, bool enabled)
        {
            string output;
            int code = Exec("/Change /TN \"" + name + "\" " + (enabled ? "/ENABLE" : "/DISABLE"), out output);
            if (code != 0) throw new InvalidOperationException("Could not change task " + name + ": " + output);
        }

        public static void Delete(string name)
        {
            string output;
            int code = Exec("/Delete /TN \"" + name + "\" /F", out output);
            if (code != 0) throw new InvalidOperationException("Could not delete task " + name + ": " + output);
        }

        // Stops a task and waits up to ten seconds for it to leave the Running state.
        public static void StopAndWait(string name)
        {
            if (!Exists(name)) return;
            End(name);
            DateTime deadline = DateTime.UtcNow.AddSeconds(10);
            while (IsRunning(name))
            {
                if (DateTime.UtcNow >= deadline) throw new TimeoutException("Could not stop task " + name + "; no password was reset.");
                Thread.Sleep(100);
            }
        }

        public static bool IsRunning(string name)
        {
            Type serviceType = Type.GetTypeFromProgID("Schedule.Service");
            dynamic service = Activator.CreateInstance(serviceType);
            service.Connect();
            dynamic task = service.GetFolder("\\").GetTask(name);
            // TASK_STATE_RUNNING = 4
            return (int)task.State == 4;
        }

        private static int Exec(string arguments, out string output)
        {
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), arguments);
            info.UseShellExecute = false;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            info.CreateNoWindow = true;
            using (Process p = Process.Start(info))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();
                output = (stdout + stderr).Trim();
                return p.ExitCode;
            }
        }

        private static void WriteXml(string path, TaskDefinition d)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Encoding = Encoding.Unicode;
            settings.Indent = true;
            using (XmlWriter w = XmlWriter.Create(path, settings))
            {
                w.WriteStartDocument();
                w.WriteStartElement("Task", "http://schemas.microsoft.com/windows/2004/02/mit/task");
                w.WriteAttributeString("version", "1.2");

                w.WriteStartElement("RegistrationInfo");
                w.WriteElementString("Description", d.Description);
                w.WriteEndElement();

                w.WriteStartElement("Triggers");
                if (d.BootTrigger)
                {
                    w.WriteStartElement("BootTrigger");
                    w.WriteElementString("Enabled", "true");
                    w.WriteEndElement();
                }
                else
                {
                    w.WriteStartElement("LogonTrigger");
                    w.WriteElementString("Enabled", "true");
                    w.WriteElementString("UserId", d.TriggerSid);
                    w.WriteEndElement();
                }
                w.WriteEndElement();

                w.WriteStartElement("Principals");
                w.WriteStartElement("Principal");
                w.WriteAttributeString("id", "Author");
                w.WriteElementString("UserId", d.PrincipalSid);
                w.WriteElementString("LogonType", d.LogonType);
                w.WriteElementString("RunLevel", "HighestAvailable");
                w.WriteEndElement();
                w.WriteEndElement();

                w.WriteStartElement("Settings");
                w.WriteElementString("MultipleInstancesPolicy", "IgnoreNew");
                w.WriteElementString("DisallowStartIfOnBatteries", "false");
                w.WriteElementString("StopIfGoingOnBatteries", "false");
                w.WriteElementString("StartWhenAvailable", "true");
                w.WriteElementString("Enabled", "true");
                w.WriteElementString("Hidden", "true");
                w.WriteElementString("ExecutionTimeLimit", d.ExecutionTimeLimit);
                if (d.RestartCount > 0)
                {
                    w.WriteStartElement("RestartOnFailure");
                    w.WriteElementString("Interval", "PT1M");
                    w.WriteElementString("Count", d.RestartCount.ToString());
                    w.WriteEndElement();
                }
                w.WriteEndElement();

                w.WriteStartElement("Actions");
                w.WriteAttributeString("Context", "Author");
                w.WriteStartElement("Exec");
                w.WriteElementString("Command", d.Command);
                w.WriteElementString("Arguments", d.Arguments);
                w.WriteEndElement();
                w.WriteEndElement();

                w.WriteEndElement();
                w.WriteEndDocument();
            }
        }
    }
}
