using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace pipe
{
    class Program
    {
        
        private static string GuidSelector(string guid) => "SELECT * FROM Msvm_ComputerSystem WHERE Name='" + guid + "'";
        private static string NameSelector(string name) => "SELECT * FROM Msvm_ComputerSystem WHERE ElementName='" + name + "'";

        public static IMsvm_ComputerSystem GetVM(string name, WmiScope scope) =>
            scope.QueryInstances<IMsvm_ComputerSystem>(NameSelector(name)).FirstOrDefault();

        public static IMsvm_ComputerSystem GetVMByGuid(string guid, WmiScope scope) =>
            scope.QueryInstances<IMsvm_ComputerSystem>(GuidSelector(guid)).FirstOrDefault();

        private static Guid GetVMguid(string vmname, WmiScope scope)
        {
           

            IMsvm_ComputerSystem inst= GetVM(vmname, scope);
            string guid ="{"+ inst.Name+"}";
            return Guid.Parse(guid) ;

        }
        private static void ProcessStartNoWindow(string exepath, string args,bool WaitForExit)
        {
            try
            {

                System.Diagnostics.Process p = new System.Diagnostics.Process();
                p.StartInfo.FileName = exepath;
                p.StartInfo.Arguments = args;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardInput = true;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.LoadUserProfile = true;
                p.StartInfo.WorkingDirectory = Environment.CurrentDirectory;
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                Console.WriteLine(p.StartInfo.FileName+" " + p.StartInfo.Arguments);
                p.Start();
                if (WaitForExit)
                {
                    p.WaitForExit();
                }
            }
            catch (Exception exception)
            {
                Console.Write(exception);
            }
        }
        private static void ProcessStartWindowMaximized(string exepath, string args)
        {
            try
            {

                System.Diagnostics.Process p = new System.Diagnostics.Process();
                p.StartInfo.FileName = exepath;
                p.StartInfo.Arguments = args;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardInput = true;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.LoadUserProfile = true;
                p.StartInfo.WorkingDirectory = Environment.CurrentDirectory;
                p.StartInfo.WindowStyle = ProcessWindowStyle.Maximized;
                Console.WriteLine(p.StartInfo.FileName + " " + p.StartInfo.Arguments);
                p.Start();

            }
            catch (Exception exception)
            {
                Console.Write(exception);
            }
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[*]usage");
                Console.WriteLine("[*]pipe.exe [pipeout] [pipein] [wirehsrakpipe]");
                Console.WriteLine("[*]use default pipe");
            }



            string pipeServer_pipe_name = "spy";
            string pipeClient_pipe_name = "windbg";
            string wirehsrakpipe = "bacnet";

            if (args.Length > 0)
            {

                pipeServer_pipe_name = args[0];
            }

            if (args.Length > 1)
            {
                pipeClient_pipe_name = args[1];
            }


            if (args.Length > 2)
            {
                wirehsrakpipe = args[2];
            }

            if (args.Length > 3)
            {
                if (args[3] == "auto")
                {
                    ProcessStartNoWindow(@"C:\Windows\System32\taskkill.exe", "/f /im windbg.exe",true);
                }
            }

            // var ws = new Wireshark.WiresharkSender("bacnet", pipeServer_pipe_name, pipeClient_pipe_name, 165);
            Wireshark.WiresharkSender ws = new Wireshark.WiresharkSender(pipeServer_pipe_name, pipeClient_pipe_name);

            if (args.Length > 2)
            {
                //"C:\Program Files\Wireshark\Wireshark.exe"  -ni \\.\pipe\bacnet
                ws.WiresharCreate(wirehsrakpipe, 1);

            }

            if (args.Length > 3)
            {
                if (args[3] == "auto")
                {
                    string windbgpath = @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe";
                    string argsdbg = "-k \"com:pipe,port=\\\\.\\pipe\\" + pipeServer_pipe_name +
                                  ",baud=115200,resets=0,reconnect\"";

                    ProcessStartWindowMaximized(windbgpath, argsdbg);


                    if (args.Length > 4)
                    {
                        WmiScope scope = new WmiScope(@"root\virtualization\v2");
                        string vmname = args[4];
                        Guid vmguid = GetVMguid(vmname, scope);


                        ProcessStartNoWindow(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "-exec bypass -Command \"Stop-VM -Name " + vmname + " -TurnOff -Force\"", true);
                        //string vhdxpath = @"F:\hyperv\testuefidbgvhdxv2\Virtual Hard Disks\testuefidbgvhdxv2.vhdx";


                        ManagementObject vmobj= WmiUtilities.GetVirtualMachine(vmname, scope.Scope);
                        string vhdxpath = WmiUtilities.GetVhdSettingsPath(vmobj);

                        Console.WriteLine("[*]use vhdxpath:=>"+ vhdxpath);
                      //  string vhdxpath = @"F:\hyperv\testuefidbgvhdxv2\Virtual Hard Disks\testuefidbgvhdxv2.vhdx";
                        ProcessStartNoWindow(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "-exec bypass -Command \"Dismount-VHD '"+ vhdxpath + "'\"", true);
                        Thread.Sleep(5000);
                        ProcessStartNoWindow(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "-exec bypass -Command \"Start-VM -Name " + vmname + "\"", true);


                      ws.PipeOfferChannel(vmguid);



                    }

                }
            }

            Console.ReadLine();
            Console.WriteLine("pipe exit");
        }
    }
}
