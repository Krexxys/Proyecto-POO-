-- ==========================================================
-- SCRIPT DE BASE DE DATOS: SistemaLoginMVC
-- Incluye roles/puestos, auditoría de fechas, último ingreso
-- y contraseñas encriptadas con SHA-256.
-- ==========================================================

IF DB_ID('SistemaLoginMVC') IS NOT NULL
BEGIN
    ALTER DATABASE SistemaLoginMVC SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE SistemaLoginMVC;
END
GO

CREATE DATABASE SistemaLoginMVC;
GO

USE SistemaLoginMVC;
GO

CREATE TABLE Usuarios (
    Id INT PRIMARY KEY IDENTITY(1,1),
    NombreUsuario NVARCHAR(50) NOT NULL UNIQUE,
    Correo NVARCHAR(100) NOT NULL,
    Password NVARCHAR(100) NOT NULL,
    Puesto NVARCHAR(30) NOT NULL DEFAULT 'FOH TM',
    UltimoIngreso DATETIME NULL,
    FechaCreacion DATETIME NOT NULL DEFAULT GETDATE(),
    FechaModificacion DATETIME NULL,
    FechaEliminacion DATETIME NULL -- NULL = Activo | Con fecha = Eliminado lógicamente
);
GO

-- Insertar usuarios iniciales con contraseñas encriptadas en SHA-256
-- Nehemias -> Nehemias123 (Administrador)
-- Invitado -> Inv123 (FOH TM)
INSERT INTO Usuarios (NombreUsuario, Correo, Password, Puesto, FechaCreacion)
VALUES 
(
    'Nehemias', 
    'nehemias@prueba.com', 
    LOWER(CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', 'Nehemias123'), 2)), 
    'Administrador', 
    GETDATE()
),
(
    'Invitado', 
    'invitado@prueba.com', 
    LOWER(CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', 'Inv123'), 2)), 
    'FOH TM', 
    GETDATE()
);
GO

-- Consulta de verificación
SELECT Id, NombreUsuario, Correo, Puesto, Password, UltimoIngreso, FechaCreacion, FechaModificacion, FechaEliminacion
FROM Usuarios;
GO