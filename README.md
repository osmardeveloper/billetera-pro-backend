# Billetera Pro - API Backend (Node.js &amp; Express)

Este es el servidor de API para la aplicación Billetera Pro, desarrollado en Node.js con Express y persistencia mediante Mongoose ORM conectado a MongoDB.

---

## 🛠️ Tecnologías

- **Servidor**: Node.js &amp; Express
- **Base de Datos**: MongoDB (mediante Mongoose ORM)
- **Seguridad**: JWT (JSON Web Tokens) para sesiones y bcryptjs para contraseñas de usuarios.

---

## ⚙️ Variables de Entorno (`.env`)

Crea un archivo `.env` en la raíz de esta carpeta a partir de `.env.example`:

```env
MASTER_KEY=dev2026
MONGODB_URI=mongodb+srv://tu_usuario:tu_clave@tu_cluster.mongodb.net/billetera_pro
```

- `MASTER_KEY`: Clave de seguridad requerida para realizar ediciones de usuarios y gastos, y eliminaciones de cualquier tipo.
- `MONGODB_URI`: Cadena de conexión para conectar el backend con tu base de datos de MongoDB.

---

## 🏃 Instalación y Ejecución Standalone

Si deseas iniciar el backend por separado del frontend:

1. **Instalar dependencias**:
   ```bash
   npm install
   ```

2. **Ejecutar en desarrollo (con Nodemon)**:
   ```bash
   npm run dev
   ```
   El servidor backend correrá en [http://localhost:5001](http://localhost:5001).

---

## 🚦 Endpoints de la API

### Autenticación (`/api/auth`)
- `POST /api/auth/login` - Inicia sesión de usuario (retorna un token JWT).

### Usuarios (`/api/users`)
- `GET /api/users` - Lista todos los usuarios.
- `POST /api/users` - Registra un nuevo usuario.
- `PUT /api/users/:id` - Edita un usuario (Requiere Clave Maestra).
- `DELETE /api/users/:id` - Elimina un usuario y limpia sus gastos asociados en cascada (Requiere Clave Maestra y Motivo de eliminación).

### Gastos (`/api/expenses`)
- `GET /api/expenses` - Lista gastos paginados y filtrados.
- `POST /api/expenses` - Registra un nuevo gasto.
- `PUT /api/expenses/:id` - Edita el monto de un gasto (Requiere Clave Maestra).
- `DELETE /api/expenses/:id` - Elimina un gasto (Requiere Clave Maestra y Motivo de eliminación).

### Auditoría (`/api/logs`)
- `GET /api/logs` - Lista todos los logs de eliminaciones (Solo Administradores).
