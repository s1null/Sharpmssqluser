using System;

namespace Sharpmssqluser
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                ShowUsage();
                return 1;
            }

            try
            {
                var config = ParseArguments(args);
                if (config == null)
                {
                    ShowUsage();
                    return 1;
                }

                return ExecuteCommand(config);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Execution failed: " + ex.Message);
                return 1;
            }
        }

        static void ShowUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  Add User:");
            Console.WriteLine("    Sharpmssqluser.exe add -s <server> [-u <username>] [-p <password>] [-i] -tu <target_user> -tp <target_password>");
            Console.WriteLine();
            Console.WriteLine("  Delete User:");
            Console.WriteLine("    Sharpmssqluser.exe delete -s <server> [-u <username>] [-p <password>] [-i] -tu <target_user>");
            Console.WriteLine();
            Console.WriteLine("  Change Password:");
            Console.WriteLine("    Sharpmssqluser.exe changepass -s <server> [-u <username>] [-p <password>] [-i] -tu <target_user> -np <new_password>");
            Console.WriteLine();
            Console.WriteLine("Parameters:");
            Console.WriteLine("  -s    SQL Server address");
            Console.WriteLine("  -u    Connection username (or DOMAIN\\username with -i)");
            Console.WriteLine("  -p    Connection password");
            Console.WriteLine("  -i    Use integrated authentication");
            Console.WriteLine("  -tu   Target username");
            Console.WriteLine("  -tp   Target user password");
            Console.WriteLine("  -np   New password");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  Sharpmssqluser.exe add -s 192.168.1.100 -u sa -p password123 -tu backdoor -tp P@ssw0rd123");
            Console.WriteLine("  Sharpmssqluser.exe delete -s 192.168.1.100 -i -tu backdoor");
            Console.WriteLine("  Sharpmssqluser.exe add -s DC01.corp.local -i -u CORP\\sqladmin -p domain123 -tu backdoor -tp P@ssw0rd123");
        }

        static Config ParseArguments(string[] args)
        {
            var config = new Config();

            if (args.Length < 1)
                return null;

            config.Command = args[0].ToLower();

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "-s":
                        if (i + 1 < args.Length) config.Server = args[++i];
                        break;
                    case "-u":
                        if (i + 1 < args.Length) config.Username = args[++i];
                        break;
                    case "-p":
                        if (i + 1 < args.Length) config.Password = args[++i];
                        break;
                    case "-i":
                        config.IntegratedAuth = true;
                        break;
                    case "-tu":
                        if (i + 1 < args.Length) config.TargetUser = args[++i];
                        break;
                    case "-tp":
                        if (i + 1 < args.Length) config.TargetPassword = args[++i];
                        break;
                    case "-np":
                        if (i + 1 < args.Length) config.NewPassword = args[++i];
                        break;
                }
            }

            // Validate required parameters
            if (string.IsNullOrEmpty(config.Server))
            {
                Console.WriteLine("[-] Error: Must specify server address (-s)");
                return null;
            }

            if (string.IsNullOrEmpty(config.TargetUser))
            {
                Console.WriteLine("[-] Error: Must specify target username (-tu)");
                return null;
            }

            if (config.Command == "add" && string.IsNullOrEmpty(config.TargetPassword))
            {
                Console.WriteLine("[-] Error: Must specify target user password when adding user (-tp)");
                return null;
            }

            if (config.Command == "changepass" && string.IsNullOrEmpty(config.NewPassword))
            {
                Console.WriteLine("[-] Error: Must specify new password when changing password (-np)");
                return null;
            }

            if (!config.IntegratedAuth && (string.IsNullOrEmpty(config.Username) || string.IsNullOrEmpty(config.Password)))
            {
                Console.WriteLine("[-] Error: Must specify username and password for non-integrated authentication (-u and -p)");
                return null;
            }

            // For integrated auth with impersonation, both username and password are optional but if one is provided, both must be provided
            if (config.IntegratedAuth && !string.IsNullOrEmpty(config.Username) && string.IsNullOrEmpty(config.Password))
            {
                Console.WriteLine("[-] Error: When using impersonation with integrated auth, both username and password must be provided");
                return null;
            }

            return config;
        }

        static int ExecuteCommand(Config config)
        {
            try
            {
                Console.WriteLine("[*] Connecting to server: " + config.Server);

                var connectionManager = new SqlConnectionManager(
                    config.Server,
                    "master",
                    config.Username ?? "",
                    config.Password ?? "",
                    config.IntegratedAuth,
                    30);

                if (!connectionManager.TestConnection())
                {
                    Console.WriteLine("[-] Connection failed, please check connection parameters");
                    return 1;
                }

                var currentUser = connectionManager.GetCurrentUser();
                var isSysAdmin = connectionManager.IsSysAdmin();

                Console.WriteLine("[*] Current user: " + currentUser);
                Console.WriteLine("[*] SysAdmin privileges: " + (isSysAdmin ? "Yes" : "No"));

                if (!isSysAdmin && config.Command == "add")
                {
                    Console.WriteLine("[-] Warning: Current user does not have sysadmin privileges, operation may fail");
                }

                var userManager = new UserManager(connectionManager);
                bool success = false;

                switch (config.Command)
                {
                    case "add":
                        Console.WriteLine("[*] Preparing to add user: " + config.TargetUser);
                        success = userManager.AddUserWithSysAdmin(config.TargetUser, config.TargetPassword, false);
                        if (success)
                        {
                            Console.WriteLine("[+] User '" + config.TargetUser + "' added successfully and granted sysadmin role!");
                        }
                        break;

                    case "delete":
                        Console.WriteLine("[*] Preparing to delete user: " + config.TargetUser);
                        success = userManager.DeleteUser(config.TargetUser, false);
                        if (success)
                        {
                            Console.WriteLine("[+] User '" + config.TargetUser + "' deleted successfully!");
                        }
                        break;

                    case "changepass":
                        Console.WriteLine("[*] Preparing to change user password: " + config.TargetUser);
                        success = userManager.ChangePassword(config.TargetUser, config.NewPassword, false);
                        if (success)
                        {
                            Console.WriteLine("[+] Password for user '" + config.TargetUser + "' changed successfully!");
                        }
                        break;

                    default:
                        Console.WriteLine("[-] Error: Unsupported command '" + config.Command + "'");
                        return 1;
                }

                return success ? 0 : 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Execution failed: " + ex.Message);
                return 1;
            }
        }
    }

    class Config
    {
        public string Command { get; set; }
        public string Server { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public bool IntegratedAuth { get; set; }
        public string TargetUser { get; set; }
        public string TargetPassword { get; set; }
        public string NewPassword { get; set; }
    }
}