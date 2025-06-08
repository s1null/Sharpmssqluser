using System;
using System.Collections.Generic;
using System.Data.SqlClient;

namespace Sharpmssqluser
{
    public class UserManager
    {
        private readonly SqlConnectionManager _connectionManager;

        public UserManager(SqlConnectionManager connectionManager)
        {
            _connectionManager = connectionManager;
        }

        /// <summary>
        /// Add SQL Server login user and grant sysadmin role
        /// </summary>
        public bool AddUserWithSysAdmin(string username, string password, bool hideOutput)
        {
            try
            {
                using (var connection = _connectionManager.GetConnection())
                {
                    connection.Open();

                    // Check if user already exists
                    if (UserExists(connection, username))
                    {
                        if (!hideOutput) Console.WriteLine("[-] User '" + username + "' already exists");
                        return false;
                    }

                    // Get SQL Server version
                    var version = GetSqlServerVersion(connection);
                    if (!hideOutput) Console.WriteLine("[*] SQL Server Version: " + version);

                    // Create login user
                    var createLoginSql = string.Format(@"
                        CREATE LOGIN [{0}] 
                        WITH PASSWORD = '{1}', 
                        DEFAULT_DATABASE = [master], 
                        CHECK_EXPIRATION = OFF, 
                        CHECK_POLICY = OFF", username, password.Replace("'", "''"));

                    using (var command = new SqlCommand(createLoginSql, connection))
                    {
                        command.ExecuteNonQuery();
                    }

                    if (!hideOutput) Console.WriteLine("[+] Successfully created login user: " + username);

                    // Add to sysadmin role - choose syntax based on version
                    bool addRoleSuccess = false;

                    // Try new syntax first (SQL Server 2012+)
                    try
                    {
                        var newSyntaxSql = string.Format("ALTER SERVER ROLE [sysadmin] ADD MEMBER [{0}]", username);
                        using (var command = new SqlCommand(newSyntaxSql, connection))
                        {
                            command.ExecuteNonQuery();
                            addRoleSuccess = true;
                            if (!hideOutput) Console.WriteLine("[+] Added to sysadmin role using new syntax");
                        }
                    }
                    catch
                    {
                        // New syntax failed, use legacy syntax (SQL Server 2008 compatible)
                        try
                        {
                            var oldSyntaxSql = string.Format("EXEC sp_addsrvrolemember '{0}', 'sysadmin'", username.Replace("'", "''"));
                            using (var command = new SqlCommand(oldSyntaxSql, connection))
                            {
                                command.ExecuteNonQuery();
                                addRoleSuccess = true;
                                if (!hideOutput) Console.WriteLine("[+] Added to sysadmin role using legacy syntax");
                            }
                        }
                        catch (Exception ex)
                        {
                            if (!hideOutput) Console.WriteLine("[-] Failed to add to sysadmin role: " + ex.Message);
                        }
                    }

                    if (!addRoleSuccess)
                    {
                        if (!hideOutput) Console.WriteLine("[-] Unable to add user to sysadmin role");
                        return false;
                    }

                    if (!hideOutput) Console.WriteLine("[+] Successfully added user '" + username + "' to sysadmin role");

                    // Verify privileges
                    if (VerifyUserSysAdmin(connection, username))
                    {
                        if (!hideOutput) Console.WriteLine("[+] Privilege verification successful: " + username + " has sysadmin privileges");
                        return true;
                    }
                    else
                    {
                        if (!hideOutput) Console.WriteLine("[-] Privilege verification failed: " + username);
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                if (!hideOutput) Console.WriteLine("[-] Failed to add user: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Delete SQL Server login user
        /// </summary>
        public bool DeleteUser(string username, bool hideOutput)
        {
            try
            {
                using (var connection = _connectionManager.GetConnection())
                {
                    connection.Open();

                    // Check if user exists
                    if (!UserExists(connection, username))
                    {
                        if (!hideOutput) Console.WriteLine("[-] User '" + username + "' does not exist");
                        return false;
                    }

                    // Remove user database mappings (if any)
                    RemoveUserDatabaseMappings(connection, username, hideOutput);

                    // Delete login user
                    var dropLoginSql = string.Format("DROP LOGIN [{0}]", username);

                    using (var command = new SqlCommand(dropLoginSql, connection))
                    {
                        command.ExecuteNonQuery();
                    }

                    if (!hideOutput) Console.WriteLine("[+] Successfully deleted user: " + username);
                    return true;
                }
            }
            catch (Exception ex)
            {
                if (!hideOutput) Console.WriteLine("[-] Failed to delete user: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Change user password
        /// </summary>
        public bool ChangePassword(string username, string newPassword, bool hideOutput)
        {
            try
            {
                using (var connection = _connectionManager.GetConnection())
                {
                    connection.Open();

                    // Check if user exists
                    if (!UserExists(connection, username))
                    {
                        if (!hideOutput) Console.WriteLine("[-] User '" + username + "' does not exist");
                        return false;
                    }

                    // Change password
                    var changePasswordSql = string.Format(@"
                        ALTER LOGIN [{0}] 
                        WITH PASSWORD = '{1}'", username, newPassword.Replace("'", "''"));

                    using (var command = new SqlCommand(changePasswordSql, connection))
                    {
                        command.ExecuteNonQuery();
                    }

                    if (!hideOutput) Console.WriteLine("[+] Successfully changed password for user '" + username + "'");
                    return true;
                }
            }
            catch (Exception ex)
            {
                if (!hideOutput) Console.WriteLine("[-] Failed to change password: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Get SQL Server version information
        /// </summary>
        private string GetSqlServerVersion(SqlConnection connection)
        {
            try
            {
                using (var command = new SqlCommand("SELECT @@VERSION", connection))
                {
                    var result = command.ExecuteScalar();
                    return result != null ? result.ToString() : "Unknown Version";
                }
            }
            catch
            {
                return "Unknown Version";
            }
        }

        /// <summary>
        /// Check if user exists
        /// </summary>
        private bool UserExists(SqlConnection connection, string username)
        {
            var checkUserSql = "SELECT COUNT(*) FROM sys.server_principals WHERE name = @username AND type = 'S'";

            using (var command = new SqlCommand(checkUserSql, connection))
            {
                command.Parameters.AddWithValue("@username", username);
                var result = command.ExecuteScalar();
                return Convert.ToInt32(result) > 0;
            }
        }

        /// <summary>
        /// Verify if user has sysadmin privileges
        /// </summary>
        private bool VerifyUserSysAdmin(SqlConnection connection, string username)
        {
            var verifySql = @"SELECT IS_SRVROLEMEMBER('sysadmin', @username)";

            using (var command = new SqlCommand(verifySql, connection))
            {
                command.Parameters.AddWithValue("@username", username);
                var result = command.ExecuteScalar();
                return Convert.ToInt32(result) == 1;
            }
        }

        /// <summary>
        /// Remove user database mappings
        /// </summary>
        private void RemoveUserDatabaseMappings(SqlConnection connection, string username, bool hideOutput)
        {
            try
            {
                // Get all user databases (excluding system databases)
                var getDatabasesSql = @"
                    SELECT name 
                    FROM sys.databases 
                    WHERE database_id > 4 
                    AND state = 0"; // Only process online databases

                var databases = new List<string>();

                using (var command = new SqlCommand(getDatabasesSql, connection))
                {
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            databases.Add(reader.GetString(0));
                        }
                    }
                }

                // Check and remove user mappings from each database
                foreach (var dbName in databases)
                {
                    try
                    {
                        // Check if user exists in this database
                        var checkUserSql = string.Format(@"
                            USE [{0}];
                            SELECT COUNT(*) FROM sys.database_principals 
                            WHERE name = '{1}' AND type = 'S'", dbName, username.Replace("'", "''"));

                        using (var command = new SqlCommand(checkUserSql, connection))
                        {
                            var userCount = Convert.ToInt32(command.ExecuteScalar());
                            if (userCount > 0)
                            {
                                // User exists, remove mapping
                                var dropUserSql = string.Format("USE [{0}]; DROP USER [{1}]", dbName, username);

                                using (var dropCommand = new SqlCommand(dropUserSql, connection))
                                {
                                    dropCommand.ExecuteNonQuery();
                                }

                                if (!hideOutput) Console.WriteLine("[+] Removed user mapping from database '" + dbName + "'");
                            }
                        }
                    }
                    catch (Exception dbEx)
                    {
                        if (!hideOutput) Console.WriteLine("[!] Warning while processing database '" + dbName + "': " + dbEx.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                if (!hideOutput) Console.WriteLine("[!] Warning while cleaning database mappings: " + ex.Message);
            }
        }
    }
}