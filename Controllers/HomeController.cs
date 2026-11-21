using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using SistemaLoginMVC.Helpers;
using SistemaLoginMVC.Models;

namespace SistemaLoginMVC.Controllers
{
    public class HomeController : Controller
    {
        private readonly string _cadenaSql;
        private static readonly string[] PuestosOperativos = { "BOH TM", "MOH TM", "FOH TM" };

        public HomeController(IConfiguration config)
        {
            _cadenaSql = config.GetConnectionString("CadenaSQL")!;
        }

        private bool EsAdministrador()
        {
            string? usuario = HttpContext.Session.GetString("UsuarioActivo");
            string? puesto = HttpContext.Session.GetString("UsuarioPuesto");
            return string.Equals(usuario, "Nehemias", StringComparison.OrdinalIgnoreCase)
                   && string.Equals(puesto, "Administrador", StringComparison.OrdinalIgnoreCase);
        }

        public IActionResult Index()
        {
            string? usuarioActivo = HttpContext.Session.GetString("UsuarioActivo");
            if (string.IsNullOrEmpty(usuarioActivo))
            {
                return RedirectToAction("Login", "Acceso");
            }

            ViewBag.UsuarioId = HttpContext.Session.GetInt32("UsuarioId") ?? 0;
            ViewBag.NombreUsuario = usuarioActivo;
            ViewBag.CorreoUsuario = HttpContext.Session.GetString("UsuarioCorreo") ?? "";
            ViewBag.PuestoUsuario = HttpContext.Session.GetString("UsuarioPuesto") ?? "FOH TM";
            ViewBag.SesionActual = HttpContext.Session.GetString("SesionActual") ?? DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss");
            ViewBag.AccesoAnterior = HttpContext.Session.GetString("AccesoAnterior") ?? "Primer ingreso registrado";
            ViewBag.EsAdmin = EsAdministrador();

            List<Usuario> listaUsuarios = ObtenerUsuarios();
            return View(listaUsuarios);
        }

        [HttpPost]
        public IActionResult AgregarUsuario(string NombreUsuario, string Correo, string Puesto, string Password)
        {
            if (string.IsNullOrEmpty(HttpContext.Session.GetString("UsuarioActivo")))
                return RedirectToAction("Login", "Acceso");

            if (!EsAdministrador())
            {
                TempData["MensajeError"] = "Acceso denegado: solo el Administrador puede agregar usuarios desde el panel.";
                return RedirectToAction("Index");
            }

            if (!SeguridadHelper.EsPasswordSegura(Password))
            {
                TempData["MensajeError"] = "La contraseña debe tener al menos 8 caracteres, 1 letra mayúscula y 1 número.";
                return RedirectToAction("Index");
            }

            if (!PuestosOperativos.Contains(Puesto))
            {
                TempData["MensajeError"] = "Solo se permiten puestos BOH TM, MOH TM o FOH TM.";
                return RedirectToAction("Index");
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
                TempData["MensajeExito"] = "Usuario agregado correctamente con contraseña encriptada.";
            }
            catch (SqlException)
            {
                TempData["MensajeError"] = "Error: El nombre de usuario ya existe o los datos son inválidos.";
            }

            return RedirectToAction("Index");
        }

        [HttpPost]
        public IActionResult EditarUsuario(int Id, string NombreUsuario, string Correo, string Puesto, string? NuevaPassword)
        {
            if (string.IsNullOrEmpty(HttpContext.Session.GetString("UsuarioActivo")))
                return RedirectToAction("Login", "Acceso");

            if (!EsAdministrador())
            {
                TempData["MensajeError"] = "Acceso denegado: tu puesto no tiene permisos para editar usuarios.";
                return RedirectToAction("Index");
            }

            if (EsUsuarioProtegido(Id))
            {
                TempData["MensajeError"] = "El usuario Administrador 'Nehemias' está protegido y no puede ser modificado.";
                return RedirectToAction("Index");
            }

            if (!PuestosOperativos.Contains(Puesto))
            {
                TempData["MensajeError"] = "Puesto no válido. Selecciona BOH TM, MOH TM o FOH TM.";
                return RedirectToAction("Index");
            }

            if (!string.IsNullOrWhiteSpace(NuevaPassword) && !SeguridadHelper.EsPasswordSegura(NuevaPassword))
            {
                TempData["MensajeError"] = "La nueva contraseña debe tener al menos 8 caracteres, 1 letra mayúscula y 1 número.";
                return RedirectToAction("Index");
            }

            try
            {
                using (SqlConnection conexion = new SqlConnection(_cadenaSql))
                {
                    string query;
                    SqlCommand cmd;

                    if (!string.IsNullOrWhiteSpace(NuevaPassword))
                    {
                        string nuevaHash = SeguridadHelper.EncriptarSha256(NuevaPassword);
                        query = @"UPDATE Usuarios 
                                  SET NombreUsuario = @nombre, 
                                      Correo = @correo, 
                                      Puesto = @puesto,
                                      Password = @passHash, 
                                      FechaModificacion = GETDATE()
                                  WHERE Id = @id";
                        cmd = new SqlCommand(query, conexion);
                        cmd.Parameters.AddWithValue("@passHash", nuevaHash);
                    }
                    else
                    {
                        query = @"UPDATE Usuarios 
                                  SET NombreUsuario = @nombre, 
                                      Correo = @correo, 
                                      Puesto = @puesto,
                                      FechaModificacion = GETDATE()
                                  WHERE Id = @id";
                        cmd = new SqlCommand(query, conexion);
                    }

                    cmd.Parameters.AddWithValue("@id", Id);
                    cmd.Parameters.AddWithValue("@nombre", NombreUsuario.Trim());
                    cmd.Parameters.AddWithValue("@correo", Correo.Trim());
                    cmd.Parameters.AddWithValue("@puesto", Puesto);

                    conexion.Open();
                    cmd.ExecuteNonQuery();
                }

                TempData["MensajeExito"] = "Usuario actualizado correctamente (FechaModificacion registrada).";
            }
            catch (SqlException)
            {
                TempData["MensajeError"] = "Error al editar: verifica que el nombre de usuario no esté duplicado.";
            }

            return RedirectToAction("Index");
        }

        [HttpPost]
        public IActionResult EliminarUsuario(int id)
        {
            if (string.IsNullOrEmpty(HttpContext.Session.GetString("UsuarioActivo")))
                return RedirectToAction("Login", "Acceso");

            if (!EsAdministrador())
            {
                TempData["MensajeError"] = "Acceso denegado: tu puesto no tiene permisos para eliminar usuarios.";
                return RedirectToAction("Index");
            }

            if (EsUsuarioProtegido(id))
            {
                TempData["MensajeError"] = "El usuario Administrador 'Nehemias' está protegido y no puede ser eliminado.";
                return RedirectToAction("Index");
            }

            using (SqlConnection conexion = new SqlConnection(_cadenaSql))
            {
                string query = @"UPDATE Usuarios 
                                 SET FechaEliminacion = GETDATE(), FechaModificacion = GETDATE() 
                                 WHERE Id = @id";
                SqlCommand cmd = new SqlCommand(query, conexion);
                cmd.Parameters.AddWithValue("@id", id);

                conexion.Open();
                cmd.ExecuteNonQuery();
            }

            TempData["MensajeExito"] = "Usuario eliminado correctamente.";
            return RedirectToAction("Index");
        }

        [HttpPost]
        public IActionResult RestaurarUsuario(int id)
        {
            if (string.IsNullOrEmpty(HttpContext.Session.GetString("UsuarioActivo")))
                return RedirectToAction("Login", "Acceso");

            if (!EsAdministrador())
            {
                TempData["MensajeError"] = "Acceso denegado: solo el Administrador puede restaurar usuarios.";
                return RedirectToAction("Index");
            }

            using (SqlConnection conexion = new SqlConnection(_cadenaSql))
            {
                string query = @"UPDATE Usuarios 
                                 SET FechaEliminacion = NULL, FechaModificacion = GETDATE() 
                                 WHERE Id = @id";
                SqlCommand cmd = new SqlCommand(query, conexion);
                cmd.Parameters.AddWithValue("@id", id);

                conexion.Open();
                cmd.ExecuteNonQuery();
            }

            TempData["MensajeExito"] = "Usuario restaurado correctamente (FechaModificacion actualizada).";
            return RedirectToAction("Index");
        }

        private bool EsUsuarioProtegido(int id)
        {
            using (SqlConnection conexion = new SqlConnection(_cadenaSql))
            {
                string query = "SELECT NombreUsuario FROM Usuarios WHERE Id = @id";
                SqlCommand cmd = new SqlCommand(query, conexion);
                cmd.Parameters.AddWithValue("@id", id);
                conexion.Open();
                object? result = cmd.ExecuteScalar();
                return result != null && string.Equals(result.ToString(), "Nehemias", StringComparison.OrdinalIgnoreCase);
            }
        }

        private List<Usuario> ObtenerUsuarios()
        {
            List<Usuario> lista = new List<Usuario>();
            using (SqlConnection conexion = new SqlConnection(_cadenaSql))
            {
                string query = @"SELECT Id, NombreUsuario, Correo, Puesto, UltimoIngreso, 
                                        FechaCreacion, FechaModificacion, FechaEliminacion 
                                 FROM Usuarios";
                SqlCommand cmd = new SqlCommand(query, conexion);
                conexion.Open();

                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        lista.Add(new Usuario
                        {
                            Id = Convert.ToInt32(reader["Id"]),
                            NombreUsuario = reader["NombreUsuario"].ToString()!,
                            Correo = reader["Correo"].ToString()!,
                            Puesto = reader["Puesto"].ToString()!,
                            UltimoIngreso = reader["UltimoIngreso"] == DBNull.Value ? null : Convert.ToDateTime(reader["UltimoIngreso"]),
                            FechaCreacion = Convert.ToDateTime(reader["FechaCreacion"]),
                            FechaModificacion = reader["FechaModificacion"] == DBNull.Value ? null : Convert.ToDateTime(reader["FechaModificacion"]),
                            FechaEliminacion = reader["FechaEliminacion"] == DBNull.Value ? null : Convert.ToDateTime(reader["FechaEliminacion"])
                        });
                    }
                }
            }
            return lista;
        }
    }
}