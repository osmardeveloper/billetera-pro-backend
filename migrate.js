const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const db = require('./db');

const dbFile = path.join(__dirname, 'data', 'db.json');

async function runMigration() {
  console.log('Starting data migration to MongoDB...');

  if (!fs.existsSync(dbFile)) {
    console.error(`Local database file not found at: ${dbFile}. Nothing to migrate.`);
    process.exit(1);
  }

  let localDb = { users: [], expenses: [], logs: [] };
  try {
    const rawData = fs.readFileSync(dbFile, 'utf8');
    localDb = JSON.parse(rawData);
  } catch (err) {
    console.error('Error reading or parsing local db.json:', err);
    process.exit(1);
  }

  try {
    // Clear existing collections in MongoDB (to allow clean migration seeds)
    console.log('Clearing existing collections in MongoDB...');
    await db.User.deleteMany({});
    await db.Expense.deleteMany({});
    await db.AuditLog.deleteMany({});

    // 1. Migrate Users
    const usersCount = localDb.users ? localDb.users.length : 0;
    if (usersCount > 0) {
      console.log(`Migrating ${usersCount} users...`);
      const mappedUsers = localDb.users.map(u => ({
        username: u.username,
        password: u.password,
        name: u.name,
        role: u.role,
        code: u.code
      }));
      await db.User.insertMany(mappedUsers);
      console.log('Users migration successful!');
    }

    // 2. Migrate Expenses
    const expensesCount = localDb.expenses ? localDb.expenses.length : 0;
    if (expensesCount > 0) {
      console.log(`Migrating ${expensesCount} expenses...`);
      const mappedExpenses = localDb.expenses.map(e => ({
        amount: e.amount,
        method: e.method,
        date: e.date,
        description: e.description,
        ownerCode: e.ownerCode,
        ownerName: e.ownerName,
        registeredBy: e.registeredBy,
        createdAt: e.createdAt ? new Date(e.createdAt) : new Date()
      }));
      await db.Expense.insertMany(mappedExpenses);
      console.log('Expenses migration successful!');
    }

    // 3. Migrate Logs
    const logsCount = localDb.logs ? localDb.logs.length : 0;
    if (logsCount > 0) {
      console.log(`Migrating ${logsCount} audit logs...`);
      const mappedLogs = localDb.logs.map(l => ({
        type: l.type,
        action: l.action,
        targetId: l.targetId,
        targetDetails: l.targetDetails,
        deletedBy: l.deletedBy,
        reason: l.reason,
        timestamp: l.timestamp ? new Date(l.timestamp) : new Date()
      }));
      await db.AuditLog.insertMany(mappedLogs);
      console.log('Audit logs migration successful!');
    }

    console.log('--- Migration completed successfully! ---');
  } catch (err) {
    console.error('Migration failed with error:', err);
  } finally {
    mongoose.connection.close();
    console.log('Database connection closed.');
    process.exit(0);
  }
}

// Wait for mongoose to open its connection before starting the migration
if (mongoose.connection.readyState === 1) {
  runMigration();
} else {
  mongoose.connection.once('open', () => {
    runMigration();
  });
}
