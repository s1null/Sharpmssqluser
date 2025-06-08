using System;
using System.Data.SqlClient;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Runtime.InteropServices;

namespace Sharpmssqluser
{
    public class SqlConnectionManager
    {
        private readonly string _connectionString;
        private readonly string _domain;
        private readonly string _impersonateUser;
        private readonly string _impersonatePassword;
        private WindowsImpersonationContext _impersonationContext;

        public SqlConnectionManager(string server, string database, string username, string password, bool integratedSecurity, int timeout)
        {
            var builder = new SqlConnectionStringBuilder
            {
                DataSource = server,
                InitialCatalog = database,
                ConnectTimeout = timeout
            };

            if (integratedSecurity)
            {
                builder.IntegratedSecurity = true;

                // Check if username contains domain info for impersonation
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    if (username.Contains("\\"))
                    {
                        var parts = username.Split('\\');
                        _domain = parts[0];
                        _impersonateUser = parts[1];
                    }
                    else
                    {
                        _domain = "."; // Local machine
                        _impersonateUser = username;
                    }
                    _impersonatePassword = password;
                }
            }
            else
            {
                builder.UserID = username;
                builder.Password = password;
            }

            _connectionString = builder.ConnectionString;
        }

        public SqlConnection GetConnection()
        {
            // Start impersonation if needed
            if (!string.IsNullOrEmpty(_impersonateUser))
            {
                StartImpersonation();
            }

            return new SqlConnection(_connectionString);
        }

        public bool TestConnection()
        {
            try
            {
                using (var connection = GetConnection())
                {
                    connection.Open();
                    Console.WriteLine("[+] Database connection successful!");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Database connection failed: " + ex.Message);
                return false;
            }
            finally
            {
                StopImpersonation();
            }
        }

        public bool IsSysAdmin()
        {
            try
            {
                using (var connection = GetConnection())
                {
                    connection.Open();

                    using (var command = new SqlCommand("SELECT IS_SRVROLEMEMBER('sysadmin')", connection))
                    {
                        var result = command.ExecuteScalar();
                        return Convert.ToInt32(result) == 1;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to check privileges: " + ex.Message);
                return false;
            }
            finally
            {
                StopImpersonation();
            }
        }

        public string GetCurrentUser()
        {
            try
            {
                using (var connection = GetConnection())
                {
                    connection.Open();

                    using (var command = new SqlCommand("SELECT SUSER_NAME()", connection))
                    {
                        var result = command.ExecuteScalar();
                        return result != null ? result.ToString() : "Unknown";
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to get current user: " + ex.Message);
                return "Unknown";
            }
            finally
            {
                StopImpersonation();
            }
        }

        private void StartImpersonation()
        {
            if (string.IsNullOrEmpty(_impersonateUser)) return;

            try
            {
                IntPtr token = IntPtr.Zero;
                bool success = LogonUser(_impersonateUser, _domain, _impersonatePassword,
                    LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, out token);

                if (success)
                {
                    WindowsIdentity identity = new WindowsIdentity(token);
                    _impersonationContext = identity.Impersonate();
                    Console.WriteLine("[*] Impersonating user: " + _domain + "\\" + _impersonateUser);
                }
                else
                {
                    Console.WriteLine("[-] Failed to impersonate user: " + _domain + "\\" + _impersonateUser);
                }

                if (token != IntPtr.Zero)
                    CloseHandle(token);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Impersonation error: " + ex.Message);
            }
        }

        private void StopImpersonation()
        {
            if (_impersonationContext != null)
            {
                _impersonationContext.Undo();
                _impersonationContext = null;
            }
        }

        public void Dispose()
        {
            StopImpersonation();
        }

        // Windows API imports for impersonation
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private extern static bool CloseHandle(IntPtr handle);

        private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        private const int LOGON32_PROVIDER_DEFAULT = 0;
    }
}