const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Custom .env loader to support running from backend/ or root/
const loadEnv = () => {
  const envPaths = [
    path.join(__dirname, '.env'),
    path.join(__dirname, '..', '.env'),
    path.join(process.cwd(), '.env'),
    path.join(process.cwd(), 'backend', '.env')
  ];
  for (const p of envPaths) {
    if (fs.existsSync(p)) {
      const envConfig = fs.readFileSync(p, 'utf8');
      envConfig.split('\n').forEach(line => {
        const parts = line.split('=');
        if (parts.length >= 2) {
          const key = parts[0].trim();
          const value = parts.slice(1).join('=').trim();
          if (key) {
            process.env[key] = value;
          }
        }
      });
      break; // Stop at first found env file
    }
  }
};
loadEnv();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://osmarmedinarecursos_db_user:Developer2026.@socialdata.ub7aezj.mongodb.net/billetera_pro';

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB database successfully.'))
  .catch((err) => console.error('Error connecting to MongoDB:', err));

// 1. User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  code: { type: String, required: true, unique: true, uppercase: true, trim: true }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// 2. Expense Schema
const ExpenseSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  method: { type: String, enum: ['efectivo', 'nequi', 'bancolombia'], required: true, lowercase: true },
  date: { type: String, required: true }, // Format YYYY-MM-DD
  description: { type: String, default: '' },
  categoria: { type: String, default: 'Otros gastos' },
  ownerCode: { type: String, required: true, uppercase: true },
  ownerName: { type: String, required: true },
  registeredBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// 3. AuditLog Schema
const AuditLogSchema = new mongoose.Schema({
  type: { type: String, required: true },
  action: { type: String, required: true },
  targetId: { type: String, required: true },
  targetDetails: { type: String, required: true },
  deletedBy: { type: String, required: true },
  reason: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});
// Income Schema
const IncomeSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  method: { type: String, enum: ['efectivo', 'nequi', 'bancolombia'], required: true, lowercase: true },
  date: { type: String, required: true }, // Format YYYY-MM-DD
  description: { type: String, default: '' },
  ownerCode: { type: String, required: true, uppercase: true },
  ownerName: { type: String, required: true },
  registeredBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// SavingsGoal Schema
const SavingsGoalSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  monto: { type: Number, required: true },
  tiempoCantidad: { type: Number, required: true },
  tiempoUnidad: { type: String, enum: ['meses', 'años'], required: true },
  periodo: { type: String, enum: ['semanal', 'quincenal', 'mensual'], required: true },
  numeroCuotas: { type: Number, required: true },
  montoCuotas: { type: Number, required: true },
  progreso: { type: Number, default: 0 },
  completed: { type: Boolean, default: false },
  cuotas: [{
    fecha: { type: String, required: true },
    monto: { type: Number, required: true },
    leyenda: { type: String, default: '' }
  }],
  ownerCode: { type: String, required: true, uppercase: true },
  ownerName: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// ScheduledDebt Schema
const ScheduledDebtSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  monto: { type: Number, required: true },
  tiempoCantidad: { type: Number, required: true },
  tiempoUnidad: { type: String, enum: ['meses', 'años'], required: true },
  periodo: { type: String, enum: ['semanal', 'quincenal', 'mensual'], required: true },
  numeroCuotas: { type: Number, required: true },
  montoCuotas: { type: Number, required: true },
  progreso: { type: Number, default: 0 },
  completed: { type: Boolean, default: false },
  cuotas: [{
    fecha: { type: String, required: true },
    monto: { type: Number, required: true },
    leyenda: { type: String, default: '' }
  }],
  ownerCode: { type: String, required: true, uppercase: true },
  ownerName: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

const User = mongoose.model('User', UserSchema);
const Expense = mongoose.model('Expense', ExpenseSchema);
const Income = mongoose.model('Income', IncomeSchema);
const AuditLog = mongoose.model('AuditLog', AuditLogSchema);
const SavingsGoal = mongoose.model('SavingsGoal', SavingsGoalSchema);
const ScheduledDebt = mongoose.model('ScheduledDebt', ScheduledDebtSchema);

// Run migration query to set default category for any existing expense missing the field
async function migrateCategories() {
  try {
    const missingRes = await Expense.updateMany(
      { categoria: { $exists: false } },
      { $set: { categoria: 'Otros gastos' } }
    );
    if (missingRes.modifiedCount > 0) {
      console.log(`Data migration: Set default category 'Otros gastos' for ${missingRes.modifiedCount} expenses.`);
    }
  } catch (err) {
    console.error('Error migrating expense categories:', err);
  }
}

migrateCategories();

module.exports = {
  User,
  Expense,
  Income,
  AuditLog,
  SavingsGoal,
  ScheduledDebt,
  hashPassword: (password) => {
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(password, salt);
  },
  comparePassword: (password, hash) => {
    return bcrypt.compareSync(password, hash);
  }
};
