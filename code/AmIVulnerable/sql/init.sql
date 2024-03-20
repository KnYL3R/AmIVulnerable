CREATE TABLE IF NOT EXISTS cve.cve(
    cve_number VARCHAR(20) PRIMARY KEY NOT NULL,
    designation VARCHAR(500) NOT NULL,
    version_affected TEXT NOT NULL,
    full_text MEDIUMTEXT NOT NULL
);