-- SQLite schema for the application

-- -----------------------------------------------------
-- Table `clients`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `clients` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `uuid` TEXT UNIQUE NOT NULL,              -- Client UUID (using TEXT for UUID in SQLite)
  `ek_cert` TEXT NOT NULL,                  -- TPM Endorsement Key Certificate
  `ek_pub` TEXT NOT NULL,                   -- TPM Endorsement Public Key PEM
  `ak` TEXT NOT NULL,                       -- TPM Attestation Key PEM
  `totp_secret` TEXT,                       -- RFC 6238 TOTP secret
  `enrolled_at` TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Enrollment timestamp (ISO8601 format)
  `name` TEXT                               -- Custom client name
);

-- -----------------------------------------------------
-- Table `baseline`
-- References `clients` table via `uuid`.
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `baseline` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `uuid` TEXT NOT NULL,                     -- Foreign key to clients.uuid
  `pcr_digest` BLOB NOT NULL,               -- TPM PCR set digest
  `ba` TEXT NOT NULL,                       -- Collected boot aggregates (stored as text)
  `ima-log` TEXT NOT NULL,                  -- IMA measurement log
  `tpm-log` BLOB NOT NULL,                  -- TPM event log
  `nonce` TEXT NOT NULL,                    -- Server nonce for this baseline
  `established_at` TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Baseline insertion timestamp
  `is_accepted` INTEGER NOT NULL DEFAULT 0, -- Flag (0=false, 1=true)
  -- Constraints
  FOREIGN KEY (`uuid`) REFERENCES `clients` (`uuid`)
    ON DELETE CASCADE -- If client is deleted, delete their baseline(s)
);

CREATE INDEX IF NOT EXISTS `idx_baseline_uuid` ON `baseline` (`uuid`);
CREATE INDEX IF NOT EXISTS `idx_baseline_nonce` ON `baseline` (`nonce`);
CREATE INDEX IF NOT EXISTS `idx_baseline_is_accepted` ON `baseline` (`is_accepted`);

-- -----------------------------------------------------
-- Table `poweron`
-- References `clients` table via `uuid`.
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `poweron` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `uuid` TEXT NOT NULL,                     -- Foreign key to clients.uuid
  `counter` INTEGER NOT NULL,               -- TPM restart counter
  -- Constraints
  UNIQUE (`uuid`),                          -- One counter per client
  FOREIGN KEY (`uuid`) REFERENCES `clients` (`uuid`)
    ON DELETE CASCADE -- If client is deleted, delete their counter
);

-- -----------------------------------------------------
-- Table `push_session`
-- References `baseline` via `baseline_id` and `clients` via `uuid`.
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `push_session` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `uuid` TEXT NOT NULL,                     -- Foreign key to clients.uuid
  `baseline_id` INTEGER NOT NULL,           -- Foreign key to baseline.id
  `opened_at` TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Session creation timestamp
  `session_nonce` TEXT UNIQUE NOT NULL,     -- UUID session nonce
  -- Constraints
  UNIQUE (`uuid`),                          -- Assuming one active session per client?
  FOREIGN KEY (`baseline_id`) REFERENCES `baseline` (`id`)
    ON DELETE CASCADE
  FOREIGN KEY (`uuid`) REFERENCES `clients` (`uuid`)
    ON DELETE CASCADE -- If client is deleted, delete their push sessions
);

CREATE INDEX IF NOT EXISTS `idx_push_session_uuid` ON `push_session` (`uuid`);
CREATE INDEX IF NOT EXISTS `idx_push_session_baseline_id` ON `push_session` (`baseline_id`);

-- -----------------------------------------------------
-- Table `secured_payload`
-- References `clients` table via `uuid`.
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `secured_payload` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `uuid` TEXT NOT NULL,                     -- Foreign key to clients.uuid
  `filename_hash` TEXT NOT NULL,            -- Payload filename as SHA256 hash
  -- Constraints
  FOREIGN KEY (`uuid`) REFERENCES `clients` (`uuid`)
    ON DELETE CASCADE -- If client is deleted, delete their payloads
);

-- Index for `secured_payload`
CREATE INDEX IF NOT EXISTS `idx_secured_payload_uuid` ON `secured_payload` (`uuid`);

-- -----------------------------------------------------
-- Table `attestation_nonce`
-- References `clients` table via `uuid`.
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `attestation_nonce` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `uuid` TEXT NOT NULL,                     -- Foreign key to clients.uuid
  `attestation_nonce` TEXT UNIQUE NOT NULL, -- UUID attestation nonce
  `created_at` TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Nonce creation timestamp
  -- Constraints
  UNIQUE (`uuid`),                          -- Assuming one active nonce per client?
  FOREIGN KEY (`uuid`) REFERENCES `clients` (`uuid`)
    ON DELETE CASCADE -- If client is deleted, delete their nonce
);

-- -----------------------------------------------------
-- Table `attestation_session`
-- References `clients` table via `uuid`.
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `attestation_session` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `uuid` TEXT NOT NULL,                     -- Foreign key to clients.uuid
  `opened_at` TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Session creation timestamp
  `session_nonce` TEXT UNIQUE NOT NULL,     -- UUID session nonce
  -- Constraints
  UNIQUE (`uuid`),                          -- Assuming one active session per client?
  FOREIGN KEY (`uuid`) REFERENCES `clients` (`uuid`)
    ON DELETE CASCADE -- If client is deleted, delete their session
);

-- -----------------------------------------------------
-- Table `server_log`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `server_log` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `client_name` TEXT NULL,                             -- Client name or UUID reference, but without foreign key
  `msg` TEXT NOT NULL,                                 -- Log message
  `level` TEXT NOT NULL,                               -- Log level (e.g., 'INFO', 'ERROR')
  `logged_at` TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP  -- Logging entry timestamp
);
