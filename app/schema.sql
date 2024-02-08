PRAGMA KEY='UntitledEntailGradedCrumb';


DROP TABLE IF EXISTS healthrecords;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS prescriptions;
DROP TABLE IF EXISTS appointments;

CREATE TABLE healthrecords (
    userid TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    dob DATE NOT NULL,
    bloodtype TEXT NOT NULL,
    notes TEXT NOT NULL
);

CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid TEXT NOT NULL,
    description TEXT NOT NULL,
    transaction_date DATE NOT NULL DEFAULT CURRENT_DATE,
    price REAL NOT NULL
);

CREATE TABLE prescriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient TEXT NOT NULL,
    name TEXT NOT NULL,
    dosage TEXT NOT NULL,
    frequency TEXT NOT NULL,
    notes TEXT NOT NULL,
    date DATE NOT NULL DEFAULT CURRENT_DATE,
    doctor TEXT NOT NULL,
    isPaid BOOLEAN NOT NULL DEFAULT FALSE
);


CREATE TABLE appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid TEXT NOT NULL,
    doctor TEXT NOT NULL,
    date DATE NOT NULL,
    time TIME NOT NULL,
    notes TEXT NOT NULL
);

