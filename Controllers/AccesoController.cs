using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using SistemaLoginMVC.Helpers;

namespace SistemaLoginMVC.Controllers
{
    public class AccesoController : Controller
    {
        private readonly string _cadenaSql;
        private static readonly string[] PuestosPermitidosRegistro = { "BOH TM", "MOH TM", "FOH TM" };

        public AccesoController(IConfiguration config)
        {
            _cadenaSql = config.GetConnectionString("CadenaSQL")!;
        }

        [HttpGet]
        public IActionResult Login()
        {
            if (HttpContext.Session.GetString("UsuarioActivo") != null)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        public IActionResult Login(string usuarioOcorreo, string password)
        {
            string passwordHash = SeguridadHelper.EncriptarSha256(password ?? "");

            using (SqlConnection conexion = new SqlConnection(_cadenaSql))
            {
                string query = @"SELECT Id, NombreUsuario, Correo, Puesto, UltimoIngreso 
                                 FROM Usuarios 
                                 WHERE (NombreUsuario = @user OR Correo = @user) 
                                 AND Password = @passHash 
                                 AND FechaEliminacion IS NULL";

                SqlCommand cmd = new SqlCommand(query, conexion);
                cmd.Parameters.AddWithValue("@user", usuarioOcorreo ?? "");
                cmd.Parameters.AddWithValue("@passHash", passwordHash);

                conexion.Open();
                int idUsuario = 0;

                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        idUsuario = Convert.ToInt32(reader["Id"]);
                        string nombreUsuario = reader["NombreUsuario"].ToString()!;
                        string correo = reader["Correo"].ToString()!;
                        string puesto = reader["Puesto"].ToString()!;

                        string accesoAnterior = reader["UltimoIngreso"] == DBNull.Value
                            ? "Primer ingreso registrado"
                            : Convert.ToDateTime(reader["UltimoIngreso"]).ToString("dd/MM/yyyy HH:mm");

                        string sesionActual = DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss");

                        HttpContext.Session.SetInt32("UsuarioId", idUsuario);
                        HttpContext.Session.SetString("UsuarioActivo", nombreUsuario);
                        HttpContext.Session.SetString("UsuarioCorreo", correo);
                        HttpContext.Session.SetString("UsuarioPuesto", puesto);
                        HttpContext.Session.SetString("AccesoAnterior", accesoAnterior);
                        HttpContext.Session.SetString("SesionActual", sesionActual);
                    }
                }

                if (idUsuario > 0)
                {
                    // Actualizar UltimoIngreso en SQL Server con la fecha/hora actual
                    string updateIngreso = "UPDATE Usuarios SET UltimoIngreso = GETDATE() WHERE Id = @id";
                    SqlCommand cmdUpdate = new SqlCommand(updateIngreso, conexion);
                    cmdUpdate.Parameters.AddWithValue("@id", idUsuario);
                    cmdUpdate.ExecuteNonQuery();

                    return RedirectToAction("Index", "Home");
                }
            }

            TempData["ErrorLogin"] = "Usuario o contraseña incorrectos, o el usuario fue eliminado.";
            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult Registrarse()
        {
            if (HttpContext.Session.GetString("UsuarioActivo") != null)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        public IActionResult Registrarse(string NombreUsuario, string Correo, string Puesto, string Password, string ConfirmarPassword)
        {
            if (string.IsNullOrWhiteSpace(NombreUsuario) || string.IsNullOrWhiteSpace(Correo) || string.IsNullOrWhiteSpace(Password))
            {
                TempData["ErrorRegistro"] = "Todos los campos son obligatorios.";
                return RedirectToAction("Registrarse");
            }

            if (Password != ConfirmarPassword)
            {
                TempData["ErrorRegistro"] = "Las contraseñas no coinciden.";
                return RedirectToAction("Registrarse");
            }

            if (!SeguridadHelper.EsPasswordSegura(Password))
            {
                TempData["ErrorRegistro"] = "La contraseña debe tener al menos 8 caracteres, 1 letra mayúscula y 1 número.";
                return RedirectToAction("Registrarse");
            }

            if (!PuestosPermitidosRegistro.Contains(Puesto))
            {
                TempData["ErrorRegistro"] = "Puesto no válido. Selecciona BOH TM, MOH TM o FOH TM.";
                return RedirectToAction("Registrarse");
            }

            string passwordHash = SeguridadHelper.EncriptarSha256(Password);

            try
            {
                using (SqlConnection conexion = new SqlConnection(_cadenaSql))
                {
                    string query = @"INSERT INTO Usuarios (NombreUsuario, Correo, Password, Puesto, FechaCreacion) 
                                     VALUES (@nombre, @correo, @passHash, @puesto, GETDATE())";
                    SqlCommand cmd = new SqlCommand(query, conexion);
                    cmd.Parameters.AddWithValue("@nombre", NombreUsuario.Trim());
                    cmd.Parameters.AddWithValue("@correo", Correo.Trim());
                    cmd.Parameters.AddWithValue("@passHash", passwordHash);
                    cmd.Parameters.AddWithValue("@puesto", Puesto);

                    conexion.Open();
                    cmd.ExecuteNonQuery();
                }

                TempData["ExitoRegistro"] = "¡Cuenta creada correctamente! Ya puedes iniciar sesión.";
                return RedirectToAction("Login");
            }
            catch (SqlException)
            {
                TempData["ErrorRegistro"] = "El nombre de usuario ya existe. Intenta con otro.";
                return RedirectToAction("Registrarse");
            }
        }

        public IActionResult CerrarSesion()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Acceso");
        }
    }
}