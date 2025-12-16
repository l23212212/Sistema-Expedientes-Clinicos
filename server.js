const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();
const path = require('path');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
require('dotenv').config();

const upload = multer({ dest: 'uploads/' });


app.use(
  session({
    secret: 'secretKey',
    resave: false,
    saveUninitialized: false,
  })
);


app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  timezone: '-08:00',
});

db.connect((err) => {
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('Conexión exitosa a MySQL');
});


function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login.html');
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.session.user && req.session.user.tipo_usuario === role) {
      return next();
    }

    res.status(403).send(`
      <html><body>
      <h1>Acceso denegado</h1>
      <button onclick="window.location.href='/'">Volver</button>
      </body></html>
    `);
  };
}

function allowRoles(roles = []) {
  return (req, res, next) => {
    if (req.session.user && roles.includes(req.session.user.tipo_usuario)) {
      return next();
    }

    return res.status(403).send(`
      <html><body>
      <h1>Acceso denegado</h1>
      <button onclick="window.location.href='/'">Volver</button>
      </body></html>
    `);
  };
}

function excelDateToMySQLDate(excelDate) {
  const jsDate = new Date((excelDate - 25569) * 86400 * 1000);
  return jsDate.toISOString().split('T')[0];
}



app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


app.get('/registro', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'registro.html'));
});

app.post('/registro', async (req, res) => {
  const { nombre_usuario, password, codigo_acceso } = req.body;

  if (!nombre_usuario || !password || !codigo_acceso) {
    return res.send(`
      <h1>Todos los campos son obligatorios</h1>
      <a href="/registro.html">Volver</a>
    `);
  }

  // 1️⃣ Verificar código de acceso
  const sqlCodigo = `
    SELECT id, tipo_usuario 
    FROM codigos_acceso 
    WHERE codigo = ? AND activo = TRUE
  `;

  db.query(sqlCodigo, [codigo_acceso], async (err, results) => {
    if (err || results.length === 0) {
      return res.send(`
        <h1>Código de acceso inválido</h1>
        <a href="/registro.html">Volver</a>
      `);
    }

    const codigoId = results[0].id;

    // 2️⃣ Encriptar contraseña
    const passwordHash = await bcrypt.hash(password, 10);

    // 3️⃣ Insertar usuario
    const sqlInsert = `
      INSERT INTO usuarios (nombre_usuario, password_hash, codigo_acceso_id)
      VALUES (?, ?, ?)
    `;

    db.query(
      sqlInsert,
      [nombre_usuario, passwordHash, codigoId],
      (err) => {
        if (err) {
          return res.send(`
            <h1>Error al registrar usuario (¿usuario duplicado?)</h1>
            <a href="/registro.html">Volver</a>
          `);
        }

        res.redirect('/login.html');
      }
    );
  });
});


app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { nombre_usuario, password } = req.body;

  const sql = `
    SELECT u.id, u.nombre_usuario, u.password_hash, c.tipo_usuario
    FROM usuarios u
    JOIN codigos_acceso c ON u.codigo_acceso_id = c.id
    WHERE u.nombre_usuario = ?
  `;

  db.query(sql, [nombre_usuario], async (err, results) => {
    if (err || results.length === 0) {
      return res.send(`
        <h1>Usuario no encontrado</h1>
        <a href="/login.html">Volver</a>
      `);
    }

    const user = results[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.send(`
        <h1>Contraseña incorrecta</h1>
        <a href="/login.html">Volver</a>
      `);
    }

    // Guardar sesión
    req.session.user = {
      id: user.id,
      nombre_usuario: user.nombre_usuario,
      tipo_usuario: user.tipo_usuario,
    };

    res.redirect('/');
  });
});


app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

app.get('/menu', (req, res) => {
  const menuItems = [
    { nombre: 'Inicio', url: '/index.html' },
    { nombre: 'Equipos', url: '/equipos.html' },
    { nombre: 'Usuarios', url: '/usuarios.html' },
    { nombre: 'Búsqueda', url: '/busqueda.html' },
  ];
  res.json(menuItems);
});

app.get('/tipo-usuario', requireLogin, (req, res) => {
  res.json({ tipo_usuario: req.session.user.tipo_usuario });
});

app.get('/ver-usuarios', requireLogin, requireRole('admin'), (req, res) => {
  const sql = `
    SELECT 
      u.id,
      u.nombre_usuario,
      c.tipo_usuario
    FROM usuarios u
    JOIN codigos_acceso c ON u.codigo_acceso_id = c.id
    ORDER BY u.nombre_usuario ASC
  `;

  db.query(sql, (err, results) => {
    if (err) return res.send('Error al obtener usuarios');

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Usuarios</title>
      </head>
      <body>
        <div class="card large">
          <h1>Usuarios registrados</h1>

          <table class="styled-table">
            <thead>
              <tr>
                <th>Usuario</th>
                <th>Rol</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
    `;

    results.forEach(u => {
      html += `
        <tr>
          <td>${u.nombre_usuario}</td>
          <td>${u.tipo_usuario}</td>
          <td class="actions">
            <a class="btn edit" href="/usuarios/editar/${u.id}">Editar</a>
            <form action="/usuarios/eliminar/${u.id}" method="POST" style="display:inline;"
              onsubmit="return confirm('¿Eliminar este usuario?');">
              <button type="submit" class="btn delete">Eliminar</button>
            </form>
          </td>
        </tr>
      `;
    });

    html += `
            </tbody>
          </table>
          <br>
          <button class="btn back" onclick="window.location.href='/'">Volver</button>
        </div>
      </body>
      </html>
    `;

    res.send(html);
  });
});


app.get('/usuarios/editar/:id', requireLogin, requireRole('admin'), (req, res) => {
  const { id } = req.params;

  const sql = `
    SELECT 
      u.id,
      u.nombre_usuario,
      c.tipo_usuario
    FROM usuarios u
    JOIN codigos_acceso c ON u.codigo_acceso_id = c.id
    WHERE u.id = ?
  `;

  db.query(sql, [id], (err, results) => {
    if (err || results.length === 0) return res.send('Usuario no encontrado');

    const u = results[0];

    res.send(`
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Editar Usuario</title>
      </head>
      <body>
        <div class="card">
          <h1>Editar Usuario</h1>

          <form class="form-grid" method="POST" action="/usuarios/editar/${u.id}">
            <label>Nombre de usuario</label>
            <input type="text" name="nombre_usuario" value="${u.nombre_usuario}" required>

            <label>Rol</label>
            <select name="tipo_usuario">
              <option value="admin" ${u.tipo_usuario === 'admin' ? 'selected' : ''}>Admin</option>
              <option value="medico" ${u.tipo_usuario === 'medico' ? 'selected' : ''}>Médico</option>
            </select>

            <button type="submit" class="btn save full">Guardar cambios</button>
          </form>

          <br>
          <button class="btn back full" onclick="window.location.href='/ver-usuarios'">Volver</button>
        </div>
      </body>
      </html>
    `);
  });
});



app.post('/usuarios/editar/:id',requireLogin,requireRole('admin'),(req, res) => {
    const { id } = req.params;
    const { nombre_usuario, tipo_usuario } = req.body;

    // Obtener id del código según rol
    const sqlCodigo = `
      SELECT id FROM codigos_acceso
      WHERE tipo_usuario = ?
      LIMIT 1
    `;

    db.query(sqlCodigo, [tipo_usuario], (err, result) => {
      if (err || result.length === 0) {
        return res.send('Rol inválido');
      }

      const codigoId = result[0].id;

      const sqlUpdate = `
        UPDATE usuarios
        SET nombre_usuario = ?, codigo_acceso_id = ?
        WHERE id = ?
      `;

      db.query(sqlUpdate, [nombre_usuario, codigoId, id], err => {
        if (err) {
          console.error(err);
          return res.send('Error al actualizar usuario');
        }

        res.redirect('/ver-usuarios');
      });
    });
  }
);


app.post('/usuarios/eliminar/:id', requireLogin, requireRole('admin'), (req, res) => {
  const { id } = req.params;

  db.query('DELETE FROM usuarios WHERE id = ?', [id], (err) => {
    if (err) {
      console.error(err);
      return res.send('Error al eliminar usuario');
    }

    res.redirect('/ver-usuarios');
  });
});


app.get('/usuarios/nuevo', requireLogin, requireRole('admin'), (req, res) => {
  res.send(`
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Crear Usuario</title>
    </head>
    <body>
      <div class="card">
        <h1>Crear Usuario</h1>
        <form method="POST" action="/usuarios/nuevo" class="form-grid">
          <label>Nombre de usuario</label>
          <input type="text" name="nombre_usuario" required>

          <label>Contraseña</label>
          <input type="password" name="password" required>

          <label>Rol</label>
          <select name="tipo_usuario" required>
            <option value="admin">Admin</option>
            <option value="medico">Médico</option>
          </select>

          <button type="submit" class="btn save full">Crear Usuario</button>
        </form>
        <button class="btn back" onclick="window.location.href='/ver-usuarios'">Volver</button>
      </div>
    </body>
    </html>
  `);
});

app.post('/usuarios/nuevo', requireLogin, requireRole('admin'), async (req, res) => {
  const { nombre_usuario, password, tipo_usuario } = req.body;

  // Obtener id del código según rol
  const sqlCodigo = `SELECT id FROM codigos_acceso WHERE tipo_usuario = ? LIMIT 1`;
  db.query(sqlCodigo, [tipo_usuario], async (err, result) => {
    if (err || result.length === 0) {
      return res.send('Rol inválido');
    }

    const codigoId = result[0].id;

    // Encriptar contraseña
    const passwordHash = await bcrypt.hash(password, 10);

    // Insertar nuevo usuario
    const sqlInsert = `
      INSERT INTO usuarios (nombre_usuario, password_hash, codigo_acceso_id)
      VALUES (?, ?, ?)
    `;
    db.query(sqlInsert, [nombre_usuario, passwordHash, codigoId], (err) => {
      if (err) {
        console.error(err);
        return res.send('Error al crear usuario (¿usuario duplicado?)');
      }

      res.redirect('/ver-usuarios');
    });
  });
});




// Ruta para guardar datos en la base de datos
app.post('/submit-data', requireLogin, allowRoles(['admin', 'medico']), (req, res) => {
  const {
    name,
    birth_date,
    phone_number,
    previous_diseases,
    family_history,
    prescription_medication,
    weight,
    size,
    imc,
    emergency_contact
  } = req.body;

  let fechaFinal = birth_date;

    if (birth_date && !isNaN(birth_date)) {
    fechaFinal = excelDateToMySQLDate(birth_date);
    }

  console.log('Fecha recibida:', birth_date, typeof birth_date);
  console.log('Fecha final que se insertará:', fechaFinal);

    
  const query = `
    INSERT INTO pacientes (
      nombre_completo,
      fecha_de_nacimiento,
      no_telefono,
      enfermedades_previas,
      antecedentes_familiares,
      medicamento_prescrito,
      peso,
      talla,
      imc,
      contacto_de_emergencia
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

    const weightFinal = weight === '' ? null : weight;
    const sizeFinal   = size === '' ? null : size;
    const imcFinal    = imc === '' ? null : imc;


  db.query(
    query,
    [
      name,
      fechaFinal,
      phone_number,
      previous_diseases,
      family_history,
      prescription_medication,
      weightFinal,
      sizeFinal,
      imcFinal,
      emergency_contact
    ],
    (err) => {
      if (err) {
        console.error('❌ Error MySQL:', err);
        return res.send('Error al guardar paciente');
      }


      
    let html = `
      <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Éxito</title>
          <style>
            body { display:flex; justify-content:center; align-items:center; height:100vh; font-family: Arial, sans-serif; background-color:#f5f5f5;}
            .card { background:#fff; padding:30px; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.1); text-align:center; max-width:400px; }
            .btn.back { background-color:#2196F3;color:white;padding:8px 16px;border:none;border-radius:4px;cursor:pointer;margin-top:15px;}
          </style>
        </head>
        <body>
          <div class="card">
            <h1>Paciente guardado correctamente</h1>
            <button class="btn back" onclick="window.location.href='/'">Volver</button>
          </div>
        </body>
        </html>
    `;
      
      res.send(html);
    }
  );
});



// Ruta para mostrar los datos de la base de datos en formato HTML
app.get('/pacientes', requireLogin, allowRoles(['admin', 'medico']), (req, res) => {
  db.query('SELECT * FROM pacientes', (err, results) => {
    if (err) return res.send('Error al obtener los datos.');

    let html = `
    <html>
    <head>
      <link rel="stylesheet" href="/styles.css">
      <title>Pacientes</title>
      <style>
        body {
          display: flex;
          justify-content: center;
          align-items: flex-start;
          min-height: 100vh;
          background-color: #f5f5f5;
          margin: 0;
          padding: 20px;
          font-family: Arial, sans-serif;
        }

        .card.large {
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
          background-color: #fff;
          max-width: 95%;
        }

        .table-container {
          overflow-x: auto;
          margin-top: 20px;
        }

        table.styled-table {
          border-collapse: collapse;
          width: 100%;
          min-width: 1000px;
        }

        table.styled-table th, table.styled-table td {
          padding: 10px 12px;
          text-align: left;
          border-bottom: 1px solid #ddd;
          min-width: 120px;
        }

        table.styled-table th {
          background-color: #2196F3; /* Cambiado a azul */
          color: white;
          position: sticky;
          top: 0;
          z-index: 1;
        }

        table.styled-table tr:nth-child(even) {
          background-color: #e3f2fd; /* Azul claro para filas pares */
        }

        table.styled-table tr:hover {
          background-color: #bbdefb; /* Azul más intenso al pasar el mouse */
        }

        td.actions {
          display: flex;
          gap: 5px;
          justify-content: center;
        }

        .center {
          display: flex;
          justify-content: center;
          margin-top: 15px;
        }

        .btn {
          padding: 6px 12px;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }

        .btn.edit {
          background-color: #1976d2;
          color: white;
        }

        .btn.delete {
          background-color: #f44336;
          color: white;
        }

        .btn.back {
          background-color: #9E9E9E;
          color: white;
        }
      </style>
    </head>
    <body>
      <div class="card large">
        <h1 style="text-align:center;">Pacientes Registrados</h1>

        <div class="table-container">
          <table class="styled-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Fecha Nac.</th>
                <th>Teléfono</th>
                <th>Enfermedades Previas</th>
                <th>Antecedentes Familiares</th>
                <th>Medicamento Prescrito</th>
                <th>Peso (kg)</th>
                <th>Talla (m)</th>
                <th>IMC</th>
                <th>Contacto Emergencia</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
    `;

    results.forEach(p => {
      html += `
        <tr>
          <td>${p.nombre_completo}</td>
          <td>${p.fecha_de_nacimiento || ''}</td>
          <td>${p.no_telefono || ''}</td>
          <td>${p.enfermedades_previas || ''}</td>
          <td>${p.antecedentes_familiares || ''}</td>
          <td>${p.medicamento_prescrito || ''}</td>
          <td>${p.peso ?? ''}</td>
          <td>${p.talla ?? ''}</td>
          <td>${p.imc ?? ''}</td>
          <td>${p.contacto_de_emergencia || ''}</td>
          <td class="actions">
            <a class="btn edit" href="/pacientes/editar/${p.id}">✏️ Editar</a>
            <form action="/pacientes/eliminar/${p.id}" method="POST" onsubmit="return confirm('¿Eliminar este paciente?');">
              <button class="btn delete" type="submit">🗑️</button>
            </form>
          </td>
        </tr>
      `;
    });

    html += `
            </tbody>
          </table>
        </div>

        <div class="center">
          <button class="btn back" onclick="window.location.href='/'">Volver</button>
        </div>
      </div>
    </body>
    </html>
    `;

    res.send(html);
  });
});


app.get('/buscar-pacientes', requireLogin, allowRoles(['admin', 'medico']), (req, res) => {
  const { name } = req.query;

  if (!name) {
    return res.send(`
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h2>Ingresa un nombre para buscar</h2>
        <button onclick="window.history.back()">Volver</button>
      </body>
      </html>
    `);
  }

  const query = `
    SELECT * FROM pacientes
    WHERE nombre_completo LIKE ?
  `;

  db.query(query, [`%${name}%`], (err, results) => {
    if (err) {
      return res.send('Error al realizar la búsqueda');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Resultados de búsqueda</title>
      </head>
      <body>
        <h1>Resultados para "${name}"</h1>

        <table border="1">
          <tr>
            <th>Nombre</th>
            <th>Teléfono</th>
            <th>IMC</th>
            <th>Acciones</th>
          </tr>
    `;

    if (results.length === 0) {
      html += `
        <tr>
          <td colspan="4">No se encontraron pacientes</td>
        </tr>
      `;
    }

    results.forEach(p => {
      html += `
        <tr>
          <td>${p.nombre_completo}</td>
          <td>${p.no_telefono}</td>
          <td>${p.imc}</td>
          <td>
            <a href="/pacientes/editar/${p.id}">✏️ Editar</a>

            <form method="POST" action="/pacientes/eliminar/${p.id}" style="display:inline;"
              onsubmit="return confirm('¿Eliminar este paciente?');">
              <button type="submit">🗑️ Eliminar</button>
            </form>
          </td>
        </tr>
      `;
    });

    html += `
        </table>

        <br>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});


app.post('/buscar-pacientes', requireLogin, allowRoles(['admin', 'medico']), (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.send(`
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h2>Ingresa un nombre para buscar</h2>
        <button onclick="window.history.back()">Volver</button>
      </body>
      </html>
    `);
  }

  const query = `
    SELECT * FROM pacientes
    WHERE nombre_completo LIKE ?
  `;

  db.query(query, [`%${name}%`], (err, results) => {
    if (err) return res.send('Error al realizar la búsqueda');

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Resultados de búsqueda</title>
      </head>
      <body>
        <h1>Resultados para "${name}"</h1>

        <table border="1">
          <tr>
            <th>Nombre</th>
            <th>Teléfono</th>
            <th>IMC</th>
            <th>Acciones</th>
          </tr>
    `;

    if (results.length === 0) {
      html += `
        <tr>
          <td colspan="4">No se encontraron pacientes</td>
        </tr>
      `;
    }

    results.forEach(p => {
      html += `
        <tr>
          <td>${p.nombre_completo}</td>
          <td>${p.no_telefono}</td>
          <td>${p.imc}</td>
          <td>
            <a href="/pacientes/editar/${p.id}">✏️ Editar</a>

            <form method="POST" action="/pacientes/eliminar/${p.id}" style="display:inline;"
              onsubmit="return confirm('¿Eliminar este paciente?');">
              <button type="submit">🗑️ Eliminar</button>
            </form>
          </td>
        </tr>
      `;
    });

    html += `
        </table>
        <br>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});



app.get('/pacientes/editar/:id', requireLogin, allowRoles(['admin','medico']), (req, res) => {
  const { id } = req.params;

  db.query('SELECT * FROM pacientes WHERE id = ?', [id], (err, results) => {
    if (err || results.length === 0) {
      return res.send('Paciente no encontrado');
    }

    const p = results[0];

    res.send(`
    <html>
    <head>
    <link rel="stylesheet" href="/styles.css">
    <title>Editar Paciente</title>
    </head>
    <body>

    <div class="card">
    <h1>Editar Paciente</h1>

    <form class="form-grid" method="POST" action="/pacientes/editar/${id}">

        <label>Nombre completo</label>
        <input type="text" name="nombre_completo" value="${p.nombre_completo}" required>

        <label>Fecha de nacimiento</label>
        <input type="date" name="fecha_de_nacimiento"
        value="${new Date(p.fecha_de_nacimiento).toISOString().split('T')[0]}">

        <label>Teléfono</label>
        <input type="text" name="no_telefono" value="${p.no_telefono || ''}">

        <label>Enfermedades previas</label>
        <input type="text" name="enfermedades_previas" value="${p.enfermedades_previas || ''}">

        <label>Antecedentes familiares</label>
        <input type="text" name="antecedentes_familiares" value="${p.antecedentes_familiares || ''}">

        <label>Medicamento prescrito</label>
        <input type="text" name="medicamento_prescrito" value="${p.medicamento_prescrito || ''}">

        <label>Peso (kg)</label>
        <input type="number" step="0.01" name="peso" value="${p.peso ?? ''}">

        <label>Talla (m)</label>
        <input type="number" step="0.01" name="talla" value="${p.talla ?? ''}">

        <label>IMC</label>
        <input type="number" step="0.01" name="imc" value="${p.imc ?? ''}">

        <label>Contacto de emergencia</label>
        <input type="text" name="contacto_de_emergencia" value="${p.contacto_de_emergencia || ''}">

        <button class="btn save" type="submit">Guardar cambios</button>
    </form>

    <form method="POST" action="/pacientes/eliminar/${id}"
        onsubmit="return confirm('¿Eliminar este paciente definitivamente?');">
        <button class="btn delete full">Eliminar Paciente</button>
    </form>

    <button class="btn back" onclick="window.location.href='/'">Volver</button>
    </div>

    </body>
    </html>
    `);

  });
});



app.post('/pacientes/editar/:id', requireLogin, allowRoles(['admin','medico']), (req, res) => {
  const { id } = req.params;

  const {
    nombre_completo,
    fecha_de_nacimiento,
    no_telefono,
    enfermedades_previas,
    antecedentes_familiares,
    medicamento_prescrito,
    peso,
    talla,
    imc,
    contacto_de_emergencia
  } = req.body;
const pesoFinal  = peso  === '' ? null : peso;
const tallaFinal = talla === '' ? null : talla;
const imcFinal   = imc   === '' ? null : imc;



  const query = `
    UPDATE pacientes SET
      nombre_completo = ?,
      fecha_de_nacimiento = ?,
      no_telefono = ?,
      enfermedades_previas = ?,
      antecedentes_familiares = ?,
      medicamento_prescrito = ?,
      peso = ?,
      talla = ?,
      imc = ?,
      contacto_de_emergencia = ?
    WHERE id = ?
  `;

  db.query(query, [
  nombre_completo,
  fecha_de_nacimiento,
  no_telefono,
  enfermedades_previas,
  antecedentes_familiares,
  medicamento_prescrito,
  pesoFinal,
  tallaFinal,
  imcFinal,
  contacto_de_emergencia,
  id
  ], err => {
    if (err) return res.send('Error al actualizar');

    res.redirect('/pacientes');
  });
});


app.post('/pacientes/eliminar/:id', requireLogin, allowRoles(['admin', 'medico']), (req, res) => {
  const id = req.params.id;

  db.query('DELETE FROM pacientes WHERE id = ?', [id], (err) => {
    if (err) {
      console.error(err);
      return res.send('Error al eliminar paciente');
    }

    res.redirect('/pacientes');
  });
});


app.get('/busqueda.html',requireLogin,allowRoles(['admin', 'medico']),(req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'busqueda.html'));
  }
);


app.get('/api/pacientes/buscar',requireLogin,allowRoles(['admin', 'medico']),(req, res) => {
    const { q } = req.query;

    if (!q || q.length < 2) {
      return res.json([]);
    }

    const sql = `
      SELECT id, nombre_completo, no_telefono
      FROM pacientes
      WHERE nombre_completo LIKE ?
      LIMIT 20
    `;

    db.query(sql, [`%${q}%`], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json([]);
      }

      res.json(results);
    });
  }
);


app.post('/importar-pacientes', requireLogin, allowRoles(['admin', 'medico']), upload.single('archivo'), (req, res) => {
  if (!req.file) {
    return res.send(`
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
        <style>
          body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
          }
          .card {
            background-color: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
          }
          .btn.back {
            background-color: #2196F3;
            color: white;
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 15px;
          }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>No se subió ningún archivo</h1>
          <button class="btn back" onclick="window.location.href='/'">Volver</button>
        </div>
      </body>
      </html>
    `);
  }

  try {
    const workbook = xlsx.readFile(req.file.path);
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

    const values = data.map(p => {
      let fechaFinal = p.fecha_de_nacimiento;
      if (!isNaN(fechaFinal)) fechaFinal = excelDateToMySQLDate(fechaFinal);

      return [
        p.nombre_completo,
        fechaFinal,
        p.no_telefono,
        p.enfermedades_previas || '',
        p.antecedentes_familiares || '',
        p.medicamento_prescrito || '',
        p.peso || null,
        p.talla || null,
        p.imc || null,
        p.contacto_de_emergencia || ''
      ];
    });

    const sql = `INSERT INTO pacientes (
      nombre_completo,
      fecha_de_nacimiento,
      no_telefono,
      enfermedades_previas,
      antecedentes_familiares,
      medicamento_prescrito,
      peso,
      talla,
      imc,
      contacto_de_emergencia
    ) VALUES ?`;

    db.query(sql, [values], err => {
      if (err) {
        console.error(err);
        return res.send(`
          <html>
          <head>
            <link rel="stylesheet" href="/styles.css">
            <title>Error</title>
            <style>
              body { display:flex; justify-content:center; align-items:center; height:100vh; font-family: Arial, sans-serif; background-color:#f5f5f5;}
              .card { background:#fff; padding:30px; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.1); text-align:center; max-width:400px; }
              .btn.back { background-color:#2196F3;color:white;padding:8px 16px;border:none;border-radius:4px;cursor:pointer;margin-top:15px;}
            </style>
          </head>
          <body>
            <div class="card">
              <h1>❌ Error al importar pacientes</h1>
              <button class="btn back" onclick="window.location.href='/'">Volver</button>
            </div>
          </body>
          </html>
        `);
      }

      res.send(`
        <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Éxito</title>
          <style>
            body { display:flex; justify-content:center; align-items:center; height:100vh; font-family: Arial, sans-serif; background-color:#f5f5f5;}
            .card { background:#fff; padding:30px; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.1); text-align:center; max-width:400px; }
            .btn.back { background-color:#2196F3;color:white;padding:8px 16px;border:none;border-radius:4px;cursor:pointer;margin-top:15px;}
          </style>
        </head>
        <body>
          <div class="card">
            <h1>Pacientes importados correctamente</h1>
            <button class="btn back" onclick="window.location.href='/'">Volver</button>
          </div>
        </body>
        </html>
      `);
    });

  } catch (err) {
    console.error(err);
    res.send(`
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Error</title>
        <style>
          body { display:flex; justify-content:center; align-items:center; height:100vh; font-family: Arial, sans-serif; background-color:#f5f5f5;}
          .card { background:#fff; padding:30px; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.1); text-align:center; max-width:400px; }
          .btn.back { background-color:#2196F3;color:white;padding:8px 16px;border:none;border-radius:4px;cursor:pointer;margin-top:15px;}
        </style>
      </head>
      <body>
        <div class="card">
          <h1>Error al leer el archivo</h1>
          <button class="btn back" onclick="window.location.href='/'">Volver</button>
        </div>
      </body>
      </html>
    `);
  }
});



app.get('/pacientes-ordenados', requireLogin, allowRoles(['admin', 'medico']), (req, res) => {

  const sql = `
    SELECT *
    FROM pacientes
    ORDER BY nombre_completo ASC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      return res.send('Error al obtener los pacientes.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Pacientes ordenados</title>
      </head>
      <body>
        <div class="card large">
          <h1>Pacientes ordenados alfabéticamente</h1>

          <table class="styled-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Fecha de nacimiento</th>
                <th>Teléfono</th>
                <th>Peso (kg)</th>
                <th>Talla (m)</th>
                <th>IMC</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
    `;

    results.forEach(p => {
      html += `
        <tr>
          <td>${p.nombre_completo}</td>
          <td>${p.fecha_de_nacimiento || ''}</td>
          <td>${p.no_telefono || ''}</td>
          <td>${p.peso ?? ''}</td>
          <td>${p.talla ?? ''}</td>
          <td>${p.imc ?? ''}</td>
          <td class="actions">
            <a class="btn edit" href="/pacientes/editar/${p.id}">✏️ Editar</a>
            <form action="/pacientes/eliminar/${p.id}" method="POST" style="display:inline;" onsubmit="return confirm('¿Eliminar este paciente?');">
              <button class="btn delete" type="submit">🗑️ Eliminar</button>
            </form>
          </td>
        </tr>
      `;
    });

    html += `
            </tbody>
          </table>

          <div class="center">
            <button class="btn back" onclick="window.location.href='/'">Volver</button>
          </div>
        </div>
      </body>
      </html>
    `;

    res.send(html);
  });
});



app.listen(3000, () => {
  console.log('🚀 Servidor corriendo en http://localhost:3000');
});
