CREATE TABLE IF NOT EXISTS cve.cve(
    cve_number VARCHAR(20) PRIMARY KEY NOT NULL,
    designation VARCHAR(500) NOT NULL,
    version_affected TEXT NOT NULL,
    full_text MEDIUMTEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve.repositories(
    guid VARCHAR(36) PRIMARY KEY NOT NULL,
    repoUrl VARCHAR(500) NOT NULL,
    repoOwner VARCHAR(200) NOT NULL,
    repoDesignation VARCHAR(300) NOT NULL,
    tag VARCHAR(500) DEFAULT ''
);