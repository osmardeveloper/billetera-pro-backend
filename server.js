const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { User, Expense, Income, AuditLog, hashPassword, comparePassword } = require('./db');

const app = express();
const PORT = process.env.PORT || 5001;
const JWT_SECRET = 'BilleteraProSuperSecretKey_2026';

const allowedOrigins = [
  'http://localhost:5173',
  'https://billeterapro.netlify.app',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));
app.use(express.json());

// --- MIDDLEWARES ---

// Authenticate JWT Token
const fs = require('fs');
function logDebug(message) {
  try {
    fs.appendFileSync('/Users/macbook/Documents/billetera_pro_js/backend/debug.log', `[${new Date().toISOString()}] ${message}\n`);
  } catch (e) {
    console.error('Debug log write failed:', e);
  }
}

// Authenticate JWT Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
  
  logDebug(`Auth request to ${req.method} ${req.url} - Header: ${authHeader ? 'Exists' : 'Missing'}`);

  if (!token) {
    logDebug('Auth failed: No token provided');
    return res.status(401).json({ error: 'Acceso denegado. Token no proporcionado.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) {
      logDebug(`Auth failed: jwt.verify error: ${err.message}`);
      return res.status(403).json({ error: 'Token no válido o expirado.' });
    }
    logDebug(`Auth success: Decoded user = ${JSON.stringify(decodedUser)}`);
    req.user = decodedUser;
    next();
  });
}

// Require Admin Role
function requireAdmin(req, res, next) {
  logDebug(`requireAdmin check: req.user = ${JSON.stringify(req.user)}`);
  if (!req.user || req.user.role !== 'admin') {
    logDebug(`requireAdmin failed: user role is ${req.user ? req.user.role : 'undefined'}`);
    return res.status(403).json({ error: 'Acceso denegado. Requiere rol de administrador.' });
  }
  logDebug('requireAdmin success');
  next();
}

// Require Master Key Validation
function requireMasterKey(req, res, next) {
  const clientKey = req.headers['x-master-key'];
  const serverKey = process.env.MASTER_KEY;
  
  if (!clientKey || clientKey !== serverKey) {
    return res.status(403).json({ error: 'Acceso denegado. Clave maestra incorrecta.' });
  }
  next();
}

// --- AUTHENTICATION ROUTES ---

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña son obligatorios.' });
  }

  try {
    const user = await User.findOne({ username: username.toLowerCase() });
    
    if (!user || !comparePassword(password, user.password)) {
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
    }

    // Sign JWT token
    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role, code: user.code, name: user.name },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        name: user.name,
        role: user.role,
        code: user.code
      }
    });
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ error: 'Error interno del servidor en el inicio de sesión.' });
  }
});

// Verify token validity and return current user details
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }
    res.json(user);
  } catch (err) {
    console.error('Error fetching auth user info:', err);
    res.status(500).json({ error: 'Error al recuperar información del usuario.' });
  }
});

// --- USER MANAGEMENT ROUTES (ADMIN ONLY) ---

// Get all users (Admin Only)
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Error al obtener listado de usuarios.' });
  }
});

// Create user (Admin Only)
app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  const { username, password, name, role, code } = req.body;

  if (!username || !password || !name || !role || !code) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
  }

  if (role !== 'admin' && role !== 'user') {
    return res.status(400).json({ error: 'Rol no válido. Debe ser admin o user.' });
  }

  try {
    // Check username uniqueness
    const usernameExists = await User.findOne({ username: username.toLowerCase() });
    if (usernameExists) {
      return res.status(400).json({ error: 'El nombre de usuario ya está registrado.' });
    }

    // Check code uniqueness
    const codeExists = await User.findOne({ code: code.toUpperCase() });
    if (codeExists) {
      return res.status(400).json({ error: 'El código de propietario ya está asignado a otro usuario.' });
    }

    const newUser = new User({
      username: username.toLowerCase(),
      password: hashPassword(password),
      name,
      role,
      code: code.toUpperCase()
    });

    await newUser.save();

    // Return the created user sanitizing the password
    const sanitizedUser = newUser.toObject();
    delete sanitizedUser.password;
    res.status(201).json(sanitizedUser);
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ error: 'Error al registrar el nuevo usuario.' });
  }
});

// Update user details (Admin Only - Name, Role, Username + Master Key)
app.put('/api/users/:id', authenticateToken, requireAdmin, requireMasterKey, async (req, res) => {
  const { id } = req.params;
  const { name, role, username, password } = req.body;

  if (!name || !role || !username) {
    return res.status(400).json({ error: 'El nombre, usuario y rol son obligatorios.' });
  }

  if (role !== 'admin' && role !== 'user') {
    return res.status(400).json({ error: 'Rol no válido. Debe ser admin o user.' });
  }

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }

    // Check if username clash exists with another account
    const usernameClash = await User.findOne({ username: username.toLowerCase(), _id: { $ne: id } });
    if (usernameClash) {
      return res.status(400).json({ error: 'El nombre de usuario ya está registrado por otra cuenta.' });
    }

    // Prevent changing the seed admin's role to user to avoid accidental lockout
    if (user.username === 'admin' && role !== 'admin') {
      return res.status(400).json({ error: 'No se puede cambiar el rol del usuario administrador principal para evitar bloqueos.' });
    }

    // Update properties
    user.name = name;
    user.role = role;
    user.username = username.toLowerCase();

    // Update password if provided
    if (password && password.trim() !== '') {
      user.password = hashPassword(password);
    }

    await user.save();

    const sanitizedUser = user.toObject();
    delete sanitizedUser.password;
    res.json(sanitizedUser);
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ error: 'Error al actualizar detalles del usuario.' });
  }
});

// Delete user (Admin Only + Master Key)
app.delete('/api/users/:id', authenticateToken, requireAdmin, requireMasterKey, async (req, res) => {
  const { id } = req.params;
  const reason = req.headers['x-delete-reason'];

  if (!reason || reason.trim() === '') {
    return res.status(400).json({ error: 'El motivo de la eliminación es obligatorio.' });
  }

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }

    // Prevent deleting the main admin user to avoid locking out the system
    if (user.username === 'admin') {
      return res.status(400).json({ error: 'No se puede eliminar el usuario administrador principal.' });
    }

    await User.findByIdAndDelete(id);

    // Cascade delete user's expenses and incomes (matching ownerCode to deletedUser's code)
    const deleteExpensesRes = await Expense.deleteMany({ ownerCode: user.code });
    const deleteIncomesRes = await Income.deleteMany({ ownerCode: user.code });
    const deletedCount = deleteExpensesRes.deletedCount;
    const deletedIncomesCount = deleteIncomesRes.deletedCount;

    // Log user deletion in Audit Logs
    const newLog = new AuditLog({
      type: 'Usuario',
      action: 'Eliminación',
      targetId: user._id.toString(),
      targetDetails: `Nombre: ${user.name}, Usuario: ${user.username}, Código: ${user.code} (Se eliminaron ${deletedCount} gastos y ${deletedIncomesCount} ingresos asociados en cascada)`,
      deletedBy: req.user.username,
      reason: reason
    });
    await newLog.save();

    res.json({ message: `Usuario "${user.name}", sus ${deletedCount} gastos y ${deletedIncomesCount} ingresos asociados fueron eliminados exitosamente.` });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Error al eliminar el usuario y sus gastos.' });
  }
});

// --- EXPENSES ROUTES ---

// Get expenses (with filtering and auth logic)
app.get('/api/expenses', authenticateToken, async (req, res) => {
  const { startDate, endDate, methods, ownerCode, categorias } = req.query;
  const query = {};

  try {
    // 1. Role-based scoping
    if (req.user.role !== 'admin') {
      // Non-admin can only see their own expenses
      query.ownerCode = req.user.code;
    } else if (ownerCode) {
      // Admin can optionally filter by a specific owner code
      query.ownerCode = ownerCode.toUpperCase();
    }

    // 2. Filter by Date Range
    if (startDate && endDate) {
      query.date = { $gte: startDate, $lte: endDate };
    } else if (startDate) {
      query.date = { $gte: startDate };
    } else if (endDate) {
      query.date = { $lte: endDate };
    }

    // 3. Filter by Payment Methods
    if (methods) {
      const methodsList = methods.split(',').map(m => m.trim().toLowerCase());
      if (methodsList.length > 0 && methodsList[0] !== '') {
        query.method = { $in: methodsList };
      }
    }

    // 4. Filter by Categories
    if (categorias) {
      const categoriesList = categorias.split(',').map(c => c.trim());
      if (categoriesList.length > 0 && categoriesList[0] !== '') {
        query.categoria = { $in: categoriesList };
      }
    }

    // Find and sort by date descending
    const expenses = await Expense.find(query).sort({ date: -1 });
    res.json(expenses);
  } catch (err) {
    console.error('Error fetching expenses:', err);
    res.status(500).json({ error: 'Error al consultar el listado de gastos.' });
  }
});

// Register a new expense
app.post('/api/expenses', authenticateToken, async (req, res) => {
  const { amount, method, date, description, categoria } = req.body;

  if (amount === undefined || !method || !date) {
    return res.status(400).json({ error: 'Los campos monto, método y fecha son obligatorios.' });
  }

  const validMethods = ['efectivo', 'nequi', 'bancolombia'];
  if (!validMethods.includes(method.toLowerCase())) {
    return res.status(400).json({ error: 'Método de pago no válido. Debe ser efectivo, nequi o bancolombia.' });
  }

  if (isNaN(amount) || Number(amount) <= 0) {
    return res.status(400).json({ error: 'El monto debe ser un número positivo.' });
  }

  try {
    // Automatically assign ownerCode to the logged-in user's code
    const finalOwnerCode = req.user.code;

    // Find user details to attach owner name for ease of display
    const ownerUser = await User.findOne({ code: finalOwnerCode.toUpperCase() });
    const ownerName = ownerUser ? ownerUser.name : 'Desconocido';

    const newExpense = new Expense({
      amount: Number(amount),
      method: method.toLowerCase(),
      date,
      description: description || '',
      categoria: categoria || 'Otros gastos',
      ownerCode: finalOwnerCode.toUpperCase(),
      ownerName,
      registeredBy: req.user.username
    });

    await newExpense.save();
    res.status(201).json(newExpense);
  } catch (err) {
    console.error('Error creating expense:', err);
    res.status(500).json({ error: 'Error al registrar el gasto.' });
  }
});

// Register multiple expenses in bulk
app.post('/api/expenses/bulk', authenticateToken, async (req, res) => {
  const expensesData = req.body;
  logDebug(`Bulk insert requested with ${Array.isArray(expensesData) ? expensesData.length : 0} items`);

  if (!Array.isArray(expensesData) || expensesData.length === 0) {
    return res.status(400).json({ error: 'Debe proporcionar un listado de gastos válido.' });
  }

  const validMethods = ['efectivo', 'nequi', 'bancolombia'];
  
  // Validate all items
  for (let i = 0; i < expensesData.length; i++) {
    const { amount, method, date } = expensesData[i];
    if (amount === undefined || !method || !date) {
      return res.status(400).json({ error: `Fila ${i + 1}: Los campos monto, método y fecha son obligatorios.` });
    }
    if (!validMethods.includes(method.toLowerCase())) {
      return res.status(400).json({ error: `Fila ${i + 1}: Método de pago no válido.` });
    }
    if (isNaN(amount) || Number(amount) <= 0) {
      return res.status(400).json({ error: `Fila ${i + 1}: El monto debe ser un número positivo.` });
    }
  }

  try {
    const finalOwnerCode = req.user.code;
    const ownerUser = await User.findOne({ code: finalOwnerCode.toUpperCase() });
    const ownerName = ownerUser ? ownerUser.name : 'Desconocido';

    const expensesToSave = expensesData.map(item => new Expense({
      amount: Number(item.amount),
      method: item.method.toLowerCase(),
      date: item.date,
      description: item.description || '',
      categoria: item.categoria || 'Otros gastos',
      ownerCode: finalOwnerCode.toUpperCase(),
      ownerName,
      registeredBy: req.user.username
    }));

    const savedExpenses = await Expense.insertMany(expensesToSave);
    logDebug(`Bulk insert success: ${savedExpenses.length} items saved.`);
    res.status(201).json(savedExpenses);
  } catch (err) {
    console.error('Error creating bulk expenses:', err);
    res.status(500).json({ error: 'Error al registrar el listado de gastos.' });
  }
});

// Edit expense (Admin or Owner)
app.put('/api/expenses/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { amount, method, date, description, categoria } = req.body;

  if (amount === undefined) {
    return res.status(400).json({ error: 'El campo monto es obligatorio.' });
  }

  if (isNaN(amount) || Number(amount) <= 0) {
    return res.status(400).json({ error: 'El monto debe ser un número positivo.' });
  }

  try {
    const expense = await Expense.findById(id);
    if (!expense) {
      return res.status(404).json({ error: 'Gasto no encontrado.' });
    }

    // Authorization: User must be an admin OR the owner of the expense
    if (req.user.role !== 'admin' && expense.ownerCode !== req.user.code) {
      return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para editar este gasto.' });
    }

    // Update values (amount is mandatory; method, date, and description are optional fallbacks)
    expense.amount = Number(amount);
    
    if (method) {
      const validMethods = ['efectivo', 'nequi', 'bancolombia'];
      if (!validMethods.includes(method.toLowerCase())) {
        return res.status(400).json({ error: 'Método de pago no válido.' });
      }
      expense.method = method.toLowerCase();
    }
    
    if (date) {
      expense.date = date;
    }
    
    if (description !== undefined) {
      expense.description = description;
    }

    if (categoria !== undefined) {
      expense.categoria = categoria;
    }

    await expense.save();
    res.json(expense);
  } catch (err) {
    console.error('Error updating expense:', err);
    res.status(500).json({ error: 'Error al actualizar el gasto.' });
  }
});

// Delete expense (Admin or Owner)
app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const reason = req.headers['x-delete-reason'];

  if (!reason || reason.trim() === '') {
    return res.status(400).json({ error: 'El motivo de la eliminación es obligatorio.' });
  }

  try {
    const expense = await Expense.findById(id);
    if (!expense) {
      return res.status(404).json({ error: 'Gasto no encontrado.' });
    }

    // Authorization: User must be an admin OR the owner of the expense
    if (req.user.role !== 'admin' && expense.ownerCode !== req.user.code) {
      return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para eliminar este gasto.' });
    }

    await Expense.findByIdAndDelete(id);

    // Log expense deletion in Audit Logs
    const newLog = new AuditLog({
      type: 'Gasto',
      action: 'Eliminación',
      targetId: expense._id.toString(),
      targetDetails: `Monto: $${expense.amount}, Método: ${expense.method}, Fecha: ${expense.date}, Propietario: ${expense.ownerName} (${expense.ownerCode})`,
      deletedBy: req.user.username,
      reason: reason
    });
    await newLog.save();

    res.json({ message: 'Gasto eliminado exitosamente.', expense });
  } catch (err) {
    console.error('Error deleting expense:', err);
    res.status(500).json({ error: 'Error al eliminar el gasto.' });
  }
});

// --- INCOMES ROUTES ---

// Get incomes (with filtering and auth logic)
app.get('/api/incomes', authenticateToken, async (req, res) => {
  const { startDate, endDate, methods, ownerCode } = req.query;
  const query = {};

  try {
    // 1. Role-based scoping
    if (req.user.role !== 'admin') {
      // Non-admin can only see their own incomes
      query.ownerCode = req.user.code;
    } else if (ownerCode) {
      // Admin can optionally filter by a specific owner code
      query.ownerCode = ownerCode.toUpperCase();
    }

    // 2. Filter by Date Range
    if (startDate && endDate) {
      query.date = { $gte: startDate, $lte: endDate };
    } else if (startDate) {
      query.date = { $gte: startDate };
    } else if (endDate) {
      query.date = { $lte: endDate };
    }

    // 3. Filter by Payment Methods
    if (methods) {
      const methodsList = methods.split(',').map(m => m.trim().toLowerCase());
      if (methodsList.length > 0 && methodsList[0] !== '') {
        query.method = { $in: methodsList };
      }
    }

    // Find and sort by date descending
    const incomes = await Income.find(query).sort({ date: -1 });
    res.json(incomes);
  } catch (err) {
    console.error('Error fetching incomes:', err);
    res.status(500).json({ error: 'Error al consultar el listado de ingresos.' });
  }
});

// Register a new income
app.post('/api/incomes', authenticateToken, async (req, res) => {
  const { amount, method, date, description } = req.body;

  if (amount === undefined || !method || !date) {
    return res.status(400).json({ error: 'Los campos monto, método y fecha son obligatorios.' });
  }

  const validMethods = ['efectivo', 'nequi', 'bancolombia'];
  if (!validMethods.includes(method.toLowerCase())) {
    return res.status(400).json({ error: 'Método de pago no válido. Debe ser efectivo, nequi o bancolombia.' });
  }

  if (isNaN(amount) || Number(amount) <= 0) {
    return res.status(400).json({ error: 'El monto debe ser un número positivo.' });
  }

  try {
    const finalOwnerCode = req.user.code;

    // Find user details to attach owner name
    const ownerUser = await User.findOne({ code: finalOwnerCode.toUpperCase() });
    const ownerName = ownerUser ? ownerUser.name : 'Desconocido';

    const newIncome = new Income({
      amount: Number(amount),
      method: method.toLowerCase(),
      date,
      description: description || '',
      ownerCode: finalOwnerCode.toUpperCase(),
      ownerName,
      registeredBy: req.user.username
    });

    await newIncome.save();
    res.status(201).json(newIncome);
  } catch (err) {
    console.error('Error creating income:', err);
    res.status(500).json({ error: 'Error al registrar el ingreso.' });
  }
});

// Register multiple incomes in bulk
app.post('/api/incomes/bulk', authenticateToken, async (req, res) => {
  const incomesData = req.body;
  logDebug(`Bulk insert incomes requested with ${Array.isArray(incomesData) ? incomesData.length : 0} items`);

  if (!Array.isArray(incomesData) || incomesData.length === 0) {
    return res.status(400).json({ error: 'Debe proporcionar un listado de ingresos válido.' });
  }

  const validMethods = ['efectivo', 'nequi', 'bancolombia'];
  
  // Validate all items
  for (let i = 0; i < incomesData.length; i++) {
    const { amount, method, date } = incomesData[i];
    if (amount === undefined || !method || !date) {
      return res.status(400).json({ error: `Fila ${i + 1}: Los campos monto, método y fecha son obligatorios.` });
    }
    if (!validMethods.includes(method.toLowerCase())) {
      return res.status(400).json({ error: `Fila ${i + 1}: Método de pago no válido.` });
    }
    if (isNaN(amount) || Number(amount) <= 0) {
      return res.status(400).json({ error: `Fila ${i + 1}: El monto debe ser un número positivo.` });
    }
  }

  try {
    const finalOwnerCode = req.user.code;
    const ownerUser = await User.findOne({ code: finalOwnerCode.toUpperCase() });
    const ownerName = ownerUser ? ownerUser.name : 'Desconocido';

    const incomesToSave = incomesData.map(item => new Income({
      amount: Number(item.amount),
      method: item.method.toLowerCase(),
      date: item.date,
      description: item.description || '',
      ownerCode: finalOwnerCode.toUpperCase(),
      ownerName,
      registeredBy: req.user.username
    }));

    const savedIncomes = await Income.insertMany(incomesToSave);
    logDebug(`Bulk insert incomes success: ${savedIncomes.length} items saved.`);
    res.status(201).json(savedIncomes);
  } catch (err) {
    console.error('Error creating bulk incomes:', err);
    res.status(500).json({ error: 'Error al registrar el listado de ingresos.' });
  }
});

// Edit income (Admin or Owner)
app.put('/api/incomes/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { amount, method, date, description } = req.body;

  if (amount === undefined) {
    return res.status(400).json({ error: 'El campo monto es obligatorio.' });
  }

  if (isNaN(amount) || Number(amount) <= 0) {
    return res.status(400).json({ error: 'El monto debe ser un número positivo.' });
  }

  try {
    const income = await Income.findById(id);
    if (!income) {
      return res.status(404).json({ error: 'Ingreso no encontrado.' });
    }

    // Authorization: User must be an admin OR the owner of the income
    if (req.user.role !== 'admin' && income.ownerCode !== req.user.code) {
      return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para editar este ingreso.' });
    }

    income.amount = Number(amount);
    
    if (method) {
      const validMethods = ['efectivo', 'nequi', 'bancolombia'];
      if (!validMethods.includes(method.toLowerCase())) {
        return res.status(400).json({ error: 'Método de pago no válido.' });
      }
      income.method = method.toLowerCase();
    }
    
    if (date) {
      income.date = date;
    }
    
    if (description !== undefined) {
      income.description = description;
    }

    await income.save();
    res.json(income);
  } catch (err) {
    console.error('Error updating income:', err);
    res.status(500).json({ error: 'Error al actualizar el ingreso.' });
  }
});

// Delete income (Admin or Owner)
app.delete('/api/incomes/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const reason = req.headers['x-delete-reason'];

  if (!reason || reason.trim() === '') {
    return res.status(400).json({ error: 'El motivo de la eliminación es obligatorio.' });
  }

  try {
    const income = await Income.findById(id);
    if (!income) {
      return res.status(404).json({ error: 'Ingreso no encontrado.' });
    }

    // Authorization: User must be an admin OR the owner of the income
    if (req.user.role !== 'admin' && income.ownerCode !== req.user.code) {
      return res.status(403).json({ error: 'Acceso denegado. No tiene permisos para eliminar este ingreso.' });
    }

    await Income.findByIdAndDelete(id);

    // Log income deletion in Audit Logs
    const newLog = new AuditLog({
      type: 'Ingreso',
      action: 'Eliminación',
      targetId: income._id.toString(),
      targetDetails: `Monto: $${income.amount}, Método: ${income.method}, Fecha: ${income.date}, Propietario: ${income.ownerName} (${income.ownerCode})`,
      deletedBy: req.user.username,
      reason: reason
    });
    await newLog.save();

    res.json({ message: 'Ingreso eliminado exitosamente.', income });
  } catch (err) {
    console.error('Error deleting income:', err);
    res.status(500).json({ error: 'Error al eliminar el ingreso.' });
  }
});

// Get all audit logs (Admin Only)
app.get('/api/logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const logs = await AuditLog.find().sort({ timestamp: -1 });
    res.json(logs);
  } catch (err) {
    console.error('Error fetching audit logs:', err);
    res.status(500).json({ error: 'Error al consultar la bitácora de auditoría.' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
