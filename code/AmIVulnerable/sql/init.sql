CREATE TABLE IF NOT EXISTS cve.cve(
    cve_number VARCHAR(20) PRIMARY KEY NOT NULL,
    designation VARCHAR(500) NOT NULL,
    version_affected TEXT NOT NULL,
    full_text MEDIUMTEXT NOT NULL
);

/* PROCEDURE for secure index-drop */
DELIMITER //

CREATE PROCEDURE drop_index_on_designation_if_exists()
BEGIN
    DECLARE index_name VARCHAR(100);
    DECLARE table_name VARCHAR(100);
    DECLARE CONTINUE HANDLER FOR SQLSTATE '42000' SET @error = 1;

    SET index_name := 'idx_designation';
    SET table_name := 'cve';

    SET @error = 0;

    SELECT COUNT(*)
    INTO @index_exists
    FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = table_name AND index_name = index_name;

    IF @index_exists THEN
        SET @sql = CONCAT('ALTER TABLE ', table_name, ' DROP INDEX ', index_name, ';');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;

    IF @error = 1 THEN
        SELECT 'Index not found, no action taken';
    END IF;
END //

DELIMITER ;
