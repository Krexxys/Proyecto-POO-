using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SistemaLoginMVC.Helpers
{
    public static class SeguridadHelper
    {
        public static string EncriptarSha256(string texto)
        {
            if (string.IsNullOrEmpty(texto))
                return string.Empty;

            using var sha256 = SHA256.Create();
            byte[] bytes = Encoding.UTF8.GetBytes(texto);
            byte[] hash = sha256.ComputeHash(bytes);

            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        // Mínimo 8 caracteres, al menos 1 mayúscula y al menos 1 número
        public static bool EsPasswordSegura(string password)
        {
            if (string.IsNullOrEmpty(password) || password.Length < 8)
                return false;

            bool tieneMayuscula = Regex.IsMatch(password, "[A-Z]");
            bool tieneNumero = Regex.IsMatch(password, "[0-9]");

            return tieneMayuscula && tieneNumero;
        }
    }
}